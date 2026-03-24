// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Fixture: Go edge cases
// Tests: interfaces, methods with receivers, constants, iota, embedded structs,
// multiple return values, variadic functions, init functions

package shapes

import (
	"fmt"
	"math"
)

// Shape is an interface with multiple methods.
type Shape interface {
	Area() float64
	Perimeter() float64
	String() string
}

// Circle implements Shape.
type Circle struct {
	Radius float64
}

func (c Circle) Area() float64 {
	return math.Pi * c.Radius * c.Radius
}

func (c Circle) Perimeter() float64 {
	return 2 * math.Pi * c.Radius
}

func (c Circle) String() string {
	return fmt.Sprintf("Circle(r=%.2f)", c.Radius)
}

// Rectangle implements Shape with pointer receiver.
type Rectangle struct {
	Width, Height float64
}

func (r *Rectangle) Area() float64 {
	return r.Width * r.Height
}

func (r *Rectangle) Perimeter() float64 {
	return 2 * (r.Width + r.Height)
}

func (r *Rectangle) String() string {
	return fmt.Sprintf("Rect(%.2f x %.2f)", r.Width, r.Height)
}

// Embedded struct
type LabeledShape struct {
	Shape
	Label string
}

// Constants with iota
type Color int

const (
	Red Color = iota
	Green
	Blue
)

// Package-level var
var DefaultRadius = 1.0

// Multiple return values
func Divide(a, b float64) (float64, error) {
	if b == 0 {
		return 0, fmt.Errorf("division by zero")
	}
	return a / b, nil
}

// Variadic function
func SumAll(values ...float64) float64 {
	total := 0.0
	for _, v := range values {
		total += v
	}
	return total
}

// init function (special Go function, auto-called)
func init() {
	DefaultRadius = 1.0
}

// Type alias
type ShapeList = []Shape

// Function type
type ShapeFactory func(params map[string]float64) Shape
