// Fixture: basic C# entities
// Expected: 1 class, 2 methods

using System;

public class Basic
{
    public string Name { get; }

    public Basic(string name)
    {
        Name = name;
    }

    public string GetName()
    {
        return Name;
    }

    private static int HelperInternal()
    {
        return 42;
    }
}
