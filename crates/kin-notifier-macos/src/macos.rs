// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Kin's macOS notification identity.
//!
//! macOS derives a notification's sender name, icon, and Notification Center
//! grouping from the posting process's bundle. A shell script has no bundle, so
//! every `osascript ... display notification` is credited to Script Editor. This
//! binary exists only to be that bundle: it lives inside `KinNotifier.app`,
//! carries `ai.kinlab.kin`, and posts through `UNUserNotificationCenter` so the
//! notification reads as Kin.
//!
//! Exit codes are a contract the caller's fallback chain depends on. Anything
//! non-zero means "this backend could not deliver, use your fallback" and never
//! "stay silent":
//!
//! * `0` delivered
//! * `2` usage error
//! * `3` no bundle identity (running outside the `.app`)
//! * `4` authorization denied by the user
//! * `5` delivery failed or the completion handler never fired
//! * `7` authorization never requested; needs an interactive run first
//!
//! Posting deliberately never prompts. A process that exits while an
//! authorization prompt is on screen has that dismissal recorded as a permanent
//! denial, and an app denied that way never appears in System Settings, so
//! there is no way back. An unattended launchd job that prompted at 3am would
//! burn the bundle identity with nobody present to answer. Prompting is
//! confined to `--request-authorization`, which waits indefinitely by default.

use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use block2::{DynBlock, RcBlock};
use objc2::rc::Retained;
use objc2::runtime::{Bool, ProtocolObject};
use objc2::{define_class, msg_send, AnyThread, DefinedClass, MainThreadMarker};
use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};
use objc2_core_foundation::{kCFRunLoopDefaultMode, CFRunLoop};
use objc2_foundation::{NSArray, NSBundle, NSError, NSObject, NSObjectProtocol, NSSet, NSString};
use objc2_user_notifications::{
    UNAuthorizationOptions, UNAuthorizationStatus, UNMutableNotificationContent,
    UNNotificationAction, UNNotificationActionOptions, UNNotificationCategory,
    UNNotificationCategoryOptions, UNNotificationInterruptionLevel, UNNotificationRequest,
    UNNotificationResponse, UNNotificationSettings, UNNotificationSound, UNUserNotificationCenter,
    UNUserNotificationCenterDelegate,
};

const EXIT_USAGE: u8 = 2;
const EXIT_NO_BUNDLE: u8 = 3;
const EXIT_DENIED: u8 = 4;
const EXIT_UNDELIVERED: u8 = 5;
const EXIT_NOT_REQUESTED: u8 = 7;

/// How long a post waits for its delivery callback. Bounded, because an
/// unattended caller must not hang.
const POST_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a relaunch waits for the response that caused it. macOS launches
/// this bundle to deliver a button press, so an ordinary run and a
/// launched-to-handle-a-response run arrive with identical arguments, which is
/// to say none. The wait is what tells them apart, and it is short because a
/// person who ran the executable by hand is owed usage text rather than a hang.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// The category a notification carrying the update button belongs to, and the
/// button's own identifier. Both are stable strings: macOS matches a delivered
/// response against the category registered at post time, so renaming either
/// silently drops the button.
const UPDATE_CATEGORY_ID: &str = "ai.kinlab.kin.update";
const UPDATE_ACTION_ID: &str = "ai.kinlab.kin.update.apply";

/// An action a notification can carry.
///
/// The mapping from an action to the command it runs lives here and nowhere
/// else. A notification that could carry a caller-supplied command would let
/// anything able to post one get that command executed by a button press, so
/// callers choose among these names and never supply a command.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    /// Bring this machine current: install, acknowledge the restart fence,
    /// repair agent configs.
    Update,
}

impl Action {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "update" => Some(Self::Update),
            _ => None,
        }
    }

    fn identifier(self) -> &'static str {
        match self {
            Self::Update => UPDATE_ACTION_ID,
        }
    }

    fn category(self) -> &'static str {
        match self {
            Self::Update => UPDATE_CATEGORY_ID,
        }
    }

    /// The button's visible label.
    fn title(self) -> &'static str {
        match self {
            Self::Update => "Update",
        }
    }

    /// The fixed argument vector this action runs against the installed `kin`.
    fn command(self) -> &'static [&'static str] {
        match self {
            Self::Update => &["update", "--apply"],
        }
    }

    fn from_identifier(identifier: &str) -> Option<Self> {
        (identifier == UPDATE_ACTION_ID).then_some(Self::Update)
    }
}

/// The install root this bundle belongs to.
///
/// Derived from the executable's own path rather than from `$HOME`, because a
/// relaunch by the notification system inherits almost no environment, and
/// because a side-by-side or relocated install has to drive its own `kin`
/// rather than whichever one a home directory happens to hold. The bundle
/// installs at `$KIN_HOME/lib/KinNotifier.app/Contents/MacOS/KinNotifier`, so
/// the root is five levels up.
fn kin_home() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("KIN_HOME") {
        return Some(PathBuf::from(explicit));
    }
    let exe = std::env::current_exe().ok()?;
    exe.ancestors().nth(5).map(|root| root.to_path_buf())
}

/// Run an action's fixed command against the installed `kin`.
///
/// The child is spawned rather than waited on. A button press must not keep an
/// accessory app alive for the length of an update, and the chain reports its
/// own outcome by notification when it finishes, so nothing is lost by exiting
/// here.
fn run_action(action: Action) -> Result<PathBuf, String> {
    let home = kin_home().ok_or_else(|| "could not resolve the Kin install root".to_string())?;
    let binary = home.join("bin").join("kin");
    if !binary.is_file() {
        return Err(format!("no installed kin at {}", binary.display()));
    }
    Command::new(&binary)
        .args(action.command())
        .spawn()
        .map_err(|error| format!("could not run {}: {error}", binary.display()))?;
    Ok(binary)
}

/// Register the category that carries an action's button.
///
/// This runs on both sides. At post time it is what makes the button appear; on
/// a relaunch it is what lets the delivered response resolve to a category this
/// process knows.
fn register_action_category(center: &UNUserNotificationCenter, action: Action) {
    let button = UNNotificationAction::actionWithIdentifier_title_options(
        &NSString::from_str(action.identifier()),
        &NSString::from_str(action.title()),
        UNNotificationActionOptions::Foreground,
    );
    let actions = NSArray::from_slice(&[&*button]);
    let intents: Retained<NSArray<NSString>> = NSArray::new();
    let category = UNNotificationCategory::categoryWithIdentifier_actions_intentIdentifiers_options(
        &NSString::from_str(action.category()),
        &actions,
        &intents,
        UNNotificationCategoryOptions::empty(),
    );
    center.setNotificationCategories(&NSSet::from_slice(&[&*category]));
}

/// State the delegate hands back to the waiting run loop.
struct ResponseState {
    identifier: Arc<Mutex<Option<String>>>,
    done: Arc<AtomicBool>,
}

define_class!(
    // SAFETY: NSObject imposes no subclassing requirements, and this class
    // implements no Drop.
    #[unsafe(super(NSObject))]
    #[name = "KinNotifierResponseDelegate"]
    #[ivars = ResponseState]
    struct ResponseDelegate;

    unsafe impl NSObjectProtocol for ResponseDelegate {}

    unsafe impl UNUserNotificationCenterDelegate for ResponseDelegate {
        #[unsafe(method(userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:))]
        fn did_receive_response(
            &self,
            _center: &UNUserNotificationCenter,
            response: &UNNotificationResponse,
            completion: &DynBlock<dyn Fn()>,
        ) {
            if let Ok(mut slot) = self.ivars().identifier.lock() {
                *slot = Some(response.actionIdentifier().to_string());
            }
            self.ivars().done.store(true, Ordering::SeqCst);
            // The system holds the response open until this is called, so it is
            // called before any work is dispatched rather than after.
            completion.call(());
        }
    }
);

impl ResponseDelegate {
    fn new(identifier: Arc<Mutex<Option<String>>>, done: Arc<AtomicBool>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(ResponseState { identifier, done });
        unsafe { msg_send![super(this), init] }
    }
}

const USAGE: &str = "\
KinNotifier - Kin's macOS notification identity

USAGE:
    KinNotifier --title <TITLE> --body <BODY> [OPTIONS]
    KinNotifier --request-authorization
    KinNotifier --status

OPTIONS:
    --title <TITLE>       Notification title (required to post)
    --body <BODY>         Notification body (required to post)
    --level <LEVEL>       info | warn | urgent   [default: info]
                          urgent adds sound and a time-sensitive interruption
    --key <KEY>           Dedupe identity. Reposting the same key replaces the
                          existing notification rather than stacking a new one.
    --action <NAME>       Attach an action button. Only `update` is defined; it
                          runs `kin update --apply`. The command is fixed here,
                          never supplied by the caller.
    --timeout <SECONDS>   Override the wait. Posting defaults to 10 seconds;
                          --request-authorization waits indefinitely, because a
                          prompt abandoned by a dying process is recorded as a
                          permanent denial.

MODES:
    --request-authorization   Prompt for permission, post nothing. Only ever
                              call this interactively. Posting never prompts.
    --status                  Print bundle id and authorization status as JSON.
";

/// Alert urgency. Maps onto the interruption level macOS uses to decide whether
/// a notification may break through Focus, and onto whether it makes a sound.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Level {
    Info,
    Warn,
    Urgent,
}

impl Level {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "info" => Some(Self::Info),
            "warn" => Some(Self::Warn),
            "urgent" => Some(Self::Urgent),
            _ => None,
        }
    }

    fn interruption(self) -> UNNotificationInterruptionLevel {
        match self {
            // Passive never breaks through Focus and stays out of the way.
            Self::Info => UNNotificationInterruptionLevel::Passive,
            Self::Warn => UNNotificationInterruptionLevel::Active,
            // Critical would bypass Do Not Disturb entirely, but Apple gates it
            // behind a specially requested entitlement. TimeSensitive is the
            // strongest level available without one.
            Self::Urgent => UNNotificationInterruptionLevel::TimeSensitive,
        }
    }

    fn makes_sound(self) -> bool {
        self == Self::Urgent
    }
}

/// Run the main run loop until `done` is set, or until the deadline passes when
/// one is given. `None` waits indefinitely.
///
/// `UNUserNotificationCenter` completion handlers arrive asynchronously. A
/// short-lived process that posts and immediately exits loses the notification,
/// so every async call in this binary is followed by a pump.
fn pump_until(done: &AtomicBool, timeout: Option<Duration>) -> bool {
    let deadline = timeout.map(|limit| Instant::now() + limit);
    loop {
        if done.load(Ordering::SeqCst) {
            return true;
        }
        if let Some(deadline) = deadline {
            if Instant::now() >= deadline {
                return false;
            }
        }
        // Safety: reading an immutable Core Foundation mode constant.
        let mode = unsafe { kCFRunLoopDefaultMode };
        CFRunLoop::run_in_mode(mode, 0.05, true);
    }
}

fn error_message(error: *mut NSError) -> Option<String> {
    if error.is_null() {
        return None;
    }
    // Safety: checked non-null above, and the callback owns a valid error for
    // the duration of the call this runs inside.
    let error = unsafe { &*error };
    Some(error.localizedDescription().to_string())
}

/// Register this process with AppKit as a running application.
///
/// A valid bundle and a valid signature are not sufficient: UNUserNotificationCenter
/// refuses a process that the window server does not know as an app, returning
/// "Notifications are not allowed for this application" no matter how the binary
/// was launched. Instantiating the shared NSApplication is what supplies that
/// identity. Accessory activation policy is the AppKit counterpart of the
/// bundle's LSUIElement, keeping it out of the Dock and the app switcher.
fn establish_app_context() -> Option<()> {
    let marker = MainThreadMarker::new()?;
    let app = NSApplication::sharedApplication(marker);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    // Completes the launch sequence AppKit would otherwise run inside its event
    // loop, which this binary never enters.
    app.finishLaunching();
    Some(())
}

fn bundle_identifier() -> Option<String> {
    NSBundle::mainBundle()
        .bundleIdentifier()
        .map(|id| id.to_string())
}

fn status_name(status: UNAuthorizationStatus) -> &'static str {
    match status {
        UNAuthorizationStatus::NotDetermined => "not_determined",
        UNAuthorizationStatus::Denied => "denied",
        UNAuthorizationStatus::Authorized => "authorized",
        UNAuthorizationStatus::Provisional => "provisional",
        UNAuthorizationStatus::Ephemeral => "ephemeral",
        _ => "unknown",
    }
}

/// Read the current authorization status. `None` means the settings callback
/// never fired, which is treated the same as "cannot deliver".
fn authorization_status(
    center: &UNUserNotificationCenter,
    timeout: Option<Duration>,
) -> Option<UNAuthorizationStatus> {
    let done = Arc::new(AtomicBool::new(false));
    // UNAuthorizationStatus is a newtype over NSInteger, so the raw value is
    // what crosses the thread boundary out of the callback.
    let status = Arc::new(AtomicI64::new(-1));

    let handler = {
        let done = Arc::clone(&done);
        let status = Arc::clone(&status);
        RcBlock::new(move |settings: NonNull<UNNotificationSettings>| {
            // Safety: the callback owns a valid settings object for its duration.
            let settings = unsafe { settings.as_ref() };
            status.store(settings.authorizationStatus().0 as i64, Ordering::SeqCst);
            done.store(true, Ordering::SeqCst);
        })
    };
    center.getNotificationSettingsWithCompletionHandler(&handler);

    if !pump_until(&done, timeout) {
        return None;
    }
    let raw = status.load(Ordering::SeqCst);
    if raw < 0 {
        return None;
    }
    Some(UNAuthorizationStatus(raw as _))
}

/// Prompt for permission. Returns whether it was granted.
///
/// Only meaningful when the current status is `NotDetermined`; macOS answers
/// from the stored decision every time after that without showing a prompt.
fn request_authorization(center: &UNUserNotificationCenter, timeout: Option<Duration>) -> bool {
    let done = Arc::new(AtomicBool::new(false));
    let granted = Arc::new(AtomicBool::new(false));

    let handler = {
        let done = Arc::clone(&done);
        let granted = Arc::clone(&granted);
        RcBlock::new(move |ok: Bool, error: *mut NSError| {
            if let Some(message) = error_message(error) {
                eprintln!("KinNotifier: authorization request failed: {message}");
            }
            granted.store(ok.as_bool(), Ordering::SeqCst);
            done.store(true, Ordering::SeqCst);
        })
    };
    center.requestAuthorizationWithOptions_completionHandler(
        UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound,
        &handler,
    );

    pump_until(&done, timeout) && granted.load(Ordering::SeqCst)
}

/// Post one notification and wait for the delivery callback.
fn post(
    center: &UNUserNotificationCenter,
    title: &str,
    body: &str,
    level: Level,
    key: Option<&str>,
    timeout: Option<Duration>,
    action: Option<Action>,
) -> Result<(), String> {
    let content = UNMutableNotificationContent::new();
    content.setTitle(&NSString::from_str(title));
    content.setBody(&NSString::from_str(body));
    content.setInterruptionLevel(level.interruption());
    if let Some(action) = action {
        // The category has to be registered before the request is added, or the
        // delivered notification resolves to a category the system does not
        // know and arrives with no button at all.
        register_action_category(center, action);
        content.setCategoryIdentifier(&NSString::from_str(action.category()));
    }
    if level.makes_sound() {
        content.setSound(Some(&UNNotificationSound::defaultSound()));
    }
    if let Some(key) = key {
        // Thread identifier groups related alerts in Notification Center, so a
        // recurring condition reads as one conversation rather than a pile.
        content.setThreadIdentifier(&NSString::from_str(key));
    }

    // A repeated identifier replaces the existing notification instead of
    // stacking another copy, which is the dedupe the callers actually want.
    let identifier = match key {
        Some(key) => key.to_string(),
        None => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0);
            format!("kin-{}-{}", std::process::id(), nanos)
        }
    };
    let request = UNNotificationRequest::requestWithIdentifier_content_trigger(
        &NSString::from_str(&identifier),
        &content,
        None,
    );

    let done = Arc::new(AtomicBool::new(false));
    let failure: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    let handler = {
        let done = Arc::clone(&done);
        let failure = Arc::clone(&failure);
        RcBlock::new(move |error: *mut NSError| {
            if let Some(message) = error_message(error) {
                if let Ok(mut slot) = failure.lock() {
                    *slot = Some(message);
                }
            }
            done.store(true, Ordering::SeqCst);
        })
    };
    center.addNotificationRequest_withCompletionHandler(&request, Some(&handler));

    if !pump_until(&done, timeout) {
        return Err("delivery callback never fired".to_string());
    }
    // Bound to a local rather than returned as the tail expression: under
    // edition 2021 the MutexGuard temporary would otherwise outlive `failure`.
    let result = match failure.lock() {
        Ok(slot) => match slot.as_ref() {
            Some(message) => Err(message.clone()),
            None => Ok(()),
        },
        Err(_) => Err("delivery state was poisoned".to_string()),
    };
    result
}

struct Args {
    title: Option<String>,
    body: Option<String>,
    level: Level,
    key: Option<String>,
    timeout: Option<Duration>,
    request_authorization: bool,
    status: bool,
    action: Option<Action>,
}

fn parse_args() -> Result<Args, String> {
    let mut parsed = Args {
        title: None,
        body: None,
        level: Level::Info,
        key: None,
        timeout: None,
        request_authorization: false,
        status: false,
        action: None,
    };

    let mut raw = std::env::args().skip(1);
    while let Some(flag) = raw.next() {
        match flag.as_str() {
            "--title" => {
                parsed.title = Some(raw.next().ok_or("--title needs a value")?);
            }
            "--body" => {
                parsed.body = Some(raw.next().ok_or("--body needs a value")?);
            }
            "--key" => {
                parsed.key = Some(raw.next().ok_or("--key needs a value")?);
            }
            "--level" => {
                let value = raw.next().ok_or("--level needs a value")?;
                parsed.level = Level::parse(&value).ok_or(format!("unknown level: {value}"))?;
            }
            "--timeout" => {
                let value = raw.next().ok_or("--timeout needs a value")?;
                let seconds: f64 = value
                    .parse()
                    .map_err(|_| format!("timeout must be a number, got: {value}"))?;
                if !seconds.is_finite() || seconds <= 0.0 {
                    return Err(format!("timeout must be positive, got: {value}"));
                }
                parsed.timeout = Some(Duration::from_secs_f64(seconds));
            }
            "--action" => {
                let value = raw.next().ok_or("--action needs a value")?;
                parsed.action =
                    Some(Action::parse(&value).ok_or(format!("unknown action: {value}"))?);
            }
            "--request-authorization" => parsed.request_authorization = true,
            "--status" => parsed.status = true,
            "--help" | "-h" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }
    Ok(parsed)
}

/// Wait for the button press that caused this launch, and run it.
///
/// Exits usage when nothing arrives, because then this was not a relaunch at
/// all: it was a person running the executable with no arguments, and the
/// answer they are owed is the usage text. That makes the bounded wait the only
/// thing separating the two cases, which is why it is short.
fn handle_response(
    identifier: &Arc<Mutex<Option<String>>>,
    done: &Arc<AtomicBool>,
    timeout: Option<Duration>,
) -> ExitCode {
    if !pump_until(done, Some(timeout.unwrap_or(RESPONSE_TIMEOUT))) {
        eprintln!("KinNotifier: --title and --body are both required\n");
        eprint!("{USAGE}");
        return ExitCode::from(EXIT_USAGE);
    }

    let received = match identifier.lock() {
        Ok(slot) => slot.clone(),
        Err(_) => None,
    };
    let Some(received) = received else {
        eprintln!("KinNotifier: a notification response arrived carrying no action");
        return ExitCode::from(EXIT_UNDELIVERED);
    };

    // Tapping the notification body rather than the button delivers the default
    // action. That is a request to look at Kin, not a request to change this
    // machine, so it runs nothing.
    let Some(action) = Action::from_identifier(&received) else {
        return ExitCode::SUCCESS;
    };

    match run_action(action) {
        Ok(binary) => {
            println!(
                "KinNotifier: running {} {}",
                binary.display(),
                action.command().join(" ")
            );
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("KinNotifier: could not run the update action: {message}");
            ExitCode::from(EXIT_UNDELIVERED)
        }
    }
}

pub fn run() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("KinNotifier: {message}\n");
            eprint!("{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    // Guard before touching UNUserNotificationCenter: outside a bundle it
    // raises rather than returning an error, and the caller needs a clean exit
    // code so its fallback can take over.
    let Some(bundle_id) = bundle_identifier() else {
        eprintln!(
            "KinNotifier: no bundle identity. Run the executable inside KinNotifier.app, \
             not directly."
        );
        return ExitCode::from(EXIT_NO_BUNDLE);
    };

    let center = UNUserNotificationCenter::currentNotificationCenter();

    // A relaunch to deliver a button press arrives with no arguments, which is
    // also what a person typing the executable's name by hand supplies. The
    // delegate is installed before the launch sequence completes because that
    // is the only window in which the system will hand over a pending
    // response; deciding later would mean deciding after the response was
    // already dropped.
    let handling_response =
        args.title.is_none() && args.body.is_none() && !args.status && !args.request_authorization;
    let response_identifier = Arc::new(Mutex::new(None));
    let response_done = Arc::new(AtomicBool::new(false));
    let delegate = handling_response.then(|| {
        let delegate =
            ResponseDelegate::new(Arc::clone(&response_identifier), Arc::clone(&response_done));
        center.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        register_action_category(&center, Action::Update);
        delegate
    });

    if establish_app_context().is_none() {
        eprintln!("KinNotifier: could not establish an application context");
        return ExitCode::from(EXIT_NO_BUNDLE);
    }

    if handling_response {
        let _delegate = delegate;
        return handle_response(&response_identifier, &response_done, args.timeout);
    }

    if args.status {
        let status = authorization_status(&center, Some(args.timeout.unwrap_or(POST_TIMEOUT)))
            .map(status_name)
            .unwrap_or("unknown");
        println!(r#"{{"bundle_id":"{bundle_id}","authorization":"{status}"}}"#);
        return ExitCode::SUCCESS;
    }

    if args.request_authorization {
        let granted = request_authorization(&center, args.timeout);
        println!(r#"{{"bundle_id":"{bundle_id}","granted":{granted}}}"#);
        return if granted {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(EXIT_DENIED)
        };
    }

    let (Some(title), Some(body)) = (args.title.as_deref(), args.body.as_deref()) else {
        eprintln!("KinNotifier: --title and --body are both required\n");
        eprint!("{USAGE}");
        return ExitCode::from(EXIT_USAGE);
    };

    match authorization_status(&center, Some(args.timeout.unwrap_or(POST_TIMEOUT))) {
        // Never prompt from here. Posting runs unattended from watchdogs and
        // daemons, and an unanswered prompt is recorded as a permanent denial
        // that no System Settings pane can undo. Report the gap and let the
        // caller fall back for this one alert.
        Some(UNAuthorizationStatus::NotDetermined) => {
            eprintln!(
                "KinNotifier: {bundle_id} has never requested notification authorization. \
                 Run `KinNotifier --request-authorization` interactively first."
            );
            return ExitCode::from(EXIT_NOT_REQUESTED);
        }
        Some(UNAuthorizationStatus::Denied) => {
            eprintln!("KinNotifier: notifications are denied for {bundle_id} in System Settings");
            return ExitCode::from(EXIT_DENIED);
        }
        Some(_) => {}
        None => {
            eprintln!("KinNotifier: could not read notification settings");
            return ExitCode::from(EXIT_UNDELIVERED);
        }
    }

    match post(
        &center,
        title,
        body,
        args.level,
        args.key.as_deref(),
        args.timeout,
        args.action,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("KinNotifier: delivery failed: {message}");
            ExitCode::from(EXIT_UNDELIVERED)
        }
    }
}
