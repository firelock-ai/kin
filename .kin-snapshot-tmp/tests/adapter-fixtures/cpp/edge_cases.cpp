// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Fixture: C++ edge cases
// Tests: classes, inheritance, templates, namespaces, access specifiers,
// virtual methods, operator overloads, constructors, destructors, enums

#include <string>
#include <vector>
#include <memory>
#include <iostream>

namespace shapes {

// Abstract base class with virtual methods
class Shape {
public:
    virtual ~Shape() = default;
    virtual double area() const = 0;
    virtual double perimeter() const = 0;
    virtual std::string describe() const {
        return "Shape(area=" + std::to_string(area()) + ")";
    }

protected:
    std::string color_ = "black";
};

// Concrete class with inheritance
class Circle : public Shape {
public:
    explicit Circle(double radius) : radius_(radius) {}

    double area() const override {
        return 3.14159265 * radius_ * radius_;
    }

    double perimeter() const override {
        return 2 * 3.14159265 * radius_;
    }

    double radius() const { return radius_; }

private:
    double radius_;
};

// Class with operator overload
class Vector2D {
public:
    Vector2D(double x = 0, double y = 0) : x_(x), y_(y) {}

    Vector2D operator+(const Vector2D& other) const {
        return Vector2D(x_ + other.x_, y_ + other.y_);
    }

    Vector2D operator*(double scalar) const {
        return Vector2D(x_ * scalar, y_ * scalar);
    }

    bool operator==(const Vector2D& other) const {
        return x_ == other.x_ && y_ == other.y_;
    }

    double magnitude() const;

private:
    double x_, y_;
};

// Out-of-class method definition
double Vector2D::magnitude() const {
    return std::sqrt(x_ * x_ + y_ * y_);
}

// Enum class (scoped enum)
enum class Color {
    Red,
    Green,
    Blue,
};

} // namespace shapes

// Template class
template<typename T>
class Container {
public:
    void push(const T& item) {
        items_.push_back(item);
    }

    const T& at(size_t index) const {
        return items_.at(index);
    }

    size_t size() const { return items_.size(); }

private:
    std::vector<T> items_;
};

// Template function
template<typename T>
T max_value(const T& a, const T& b) {
    return (a > b) ? a : b;
}

// Free function using namespace types
std::unique_ptr<shapes::Shape> create_circle(double radius) {
    return std::make_unique<shapes::Circle>(radius);
}

// Constants
constexpr int MAX_SHAPES = 100;
static const std::string DEFAULT_COLOR = "black";
