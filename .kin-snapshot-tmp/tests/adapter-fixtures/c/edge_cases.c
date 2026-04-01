// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Fixture: C edge cases
// Tests: function pointers, enums, typedefs, static functions, structs with
// nested types, preprocessor includes, const globals, variadic functions

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Enum with explicit values
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERROR = 3,
} LogLevel;

// Struct with nested struct pointer
typedef struct {
    char* host;
    int port;
} Address;

typedef struct {
    char* name;
    Address* address;
    LogLevel level;
} Config;

// Constants
static const int MAX_CONNECTIONS = 128;
static const char* DEFAULT_HOST = "localhost";

// Function pointer typedef
typedef void (*LogHandler)(LogLevel level, const char* message);

// Static (private) helper
static int validate_port(int port) {
    return port > 0 && port < 65536;
}

// Public function with struct return
Config* create_config(const char* name, const char* host, int port) {
    if (!validate_port(port)) {
        return NULL;
    }
    Config* cfg = malloc(sizeof(Config));
    cfg->name = strdup(name);
    cfg->address = malloc(sizeof(Address));
    cfg->address->host = strdup(host);
    cfg->address->port = port;
    cfg->level = LOG_INFO;
    return cfg;
}

// Variadic function
void log_message(LogLevel level, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

// Function taking function pointer
void set_log_handler(LogHandler handler) {
    if (handler) {
        handler(LOG_INFO, "handler registered");
    }
}

// Cleanup function
void destroy_config(Config* cfg) {
    if (cfg) {
        free(cfg->name);
        if (cfg->address) {
            free(cfg->address->host);
            free(cfg->address);
        }
        free(cfg);
    }
}
