// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

// Fixture: basic Java entities
// Expected: 2 methods, 1 class

public class Basic {
    private String name;

    public Basic(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    private int helperInternal() {
        return 42;
    }
}
