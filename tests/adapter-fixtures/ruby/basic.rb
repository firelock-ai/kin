# Fixture: basic Ruby entities
# Expected: 1 class, 2 methods, 1 constant

class UserService
  DEFAULT_ROLE = "member"

  def initialize(name)
    @name = name
  end

  def display_name
    "#{@name}-#{DEFAULT_ROLE}"
  end
end

def helper_internal(name)
  UserService.new(name).display_name
end
