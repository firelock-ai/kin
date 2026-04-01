<?php
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Fixture: basic PHP entities
// Expected: 1 class, 2 methods, 1 function

class UserService
{
    public function __construct(private string $name)
    {
    }

    public function displayName(): string
    {
        return $this->name;
    }
}

function helperInternal(string $name): string
{
    $svc = new UserService($name);
    return $svc->displayName();
}
