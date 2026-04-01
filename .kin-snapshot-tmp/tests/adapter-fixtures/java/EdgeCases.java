// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Fixture: Java edge cases
// Tests: interfaces, generics, annotations, enums with methods, inner classes,
// abstract classes, default methods, static methods, lambdas, records

package com.example.shapes;

import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/** Interface with default and static methods. */
public interface Shape {
    double area();
    double perimeter();

    default String describe() {
        return String.format("%s(area=%.2f)", getClass().getSimpleName(), area());
    }

    static Shape larger(Shape a, Shape b) {
        return a.area() >= b.area() ? a : b;
    }
}

/** Abstract base with template method. */
abstract class AbstractShape implements Shape {
    private final String color;

    protected AbstractShape(String color) {
        this.color = color;
    }

    public String getColor() {
        return color;
    }

    @Override
    public String toString() {
        return describe() + " [" + color + "]";
    }
}

/** Concrete class with generics in constructor. */
class Circle extends AbstractShape {
    private final double radius;

    public Circle(double radius) {
        super("red");
        this.radius = radius;
    }

    @Override
    public double area() {
        return Math.PI * radius * radius;
    }

    @Override
    public double perimeter() {
        return 2 * Math.PI * radius;
    }

    /** Factory method. */
    public static Circle unit() {
        return new Circle(1.0);
    }
}

/** Enum with fields and methods. */
enum Color {
    RED("#FF0000"),
    GREEN("#00FF00"),
    BLUE("#0000FF");

    private final String hex;

    Color(String hex) {
        this.hex = hex;
    }

    public String getHex() {
        return hex;
    }

    public boolean isWarm() {
        return this == RED;
    }
}

/** Generic container. */
class Container<T extends Comparable<T>> {
    private final List<T> items;

    public Container(List<T> items) {
        this.items = items;
    }

    public Optional<T> max() {
        return items.stream().max(Comparable::compareTo);
    }

    /** Inner class. */
    class Iterator {
        private int index = 0;

        public boolean hasNext() {
            return index < items.size();
        }

        public T next() {
            return items.get(index++);
        }
    }
}

/** Annotation definition. */
@interface Validate {
    String message() default "validation failed";
    int priority() default 0;
}

/** Class using custom annotation. */
class Processor {
    @Validate(message = "input required", priority = 1)
    public String process(String input) {
        return input.toUpperCase();
    }

    /** Static final constant. */
    public static final int MAX_RETRIES = 3;

    /** Lambda usage. */
    public Function<String, String> getTransformer() {
        return s -> s.trim().toLowerCase();
    }
}
