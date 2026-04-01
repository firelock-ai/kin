# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

# Fixture: Python edge cases
# Tests: decorators, abstract classes, dataclasses, properties, classmethods,
# staticmethods, nested classes, async, multiple inheritance, type hints

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Protocol


class Shape(ABC):
    """Abstract base class for shapes."""

    @abstractmethod
    def area(self) -> float:
        """Calculate the area."""
        ...

    @abstractmethod
    def perimeter(self) -> float:
        """Calculate the perimeter."""
        ...

    @property
    def description(self) -> str:
        return f"{self.__class__.__name__}(area={self.area():.2f})"


@dataclass
class Circle(Shape):
    """A circle with a radius."""

    radius: float

    def area(self) -> float:
        import math
        return math.pi * self.radius ** 2

    def perimeter(self) -> float:
        import math
        return 2 * math.pi * self.radius

    @classmethod
    def unit(cls) -> "Circle":
        """Create a unit circle."""
        return cls(radius=1.0)

    @staticmethod
    def from_diameter(d: float) -> "Circle":
        return Circle(radius=d / 2)


@dataclass
class Rectangle(Shape):
    width: float
    height: float

    def area(self) -> float:
        return self.width * self.height

    def perimeter(self) -> float:
        return 2 * (self.width + self.height)


# Protocol (structural subtyping / interface)
class Drawable(Protocol):
    def draw(self, canvas: str) -> None: ...


# Multiple inheritance
class DrawableCircle(Circle, Drawable):
    def draw(self, canvas: str) -> None:
        print(f"Drawing circle on {canvas}")


# Nested class
class ShapeFactory:
    class Config:
        default_color: str = "black"
        default_fill: bool = True

    @classmethod
    def create_circle(cls, radius: float) -> Circle:
        return Circle(radius=radius)


# Async function
async def fetch_shapes(url: str) -> List[Shape]:
    return []


# Lambda and higher-order function
sort_by_area = lambda shapes: sorted(shapes, key=lambda s: s.area())


# Constants
MAX_SHAPES: int = 100
DEFAULT_COLOR: str = "blue"


# Generator function
def shape_areas(shapes: List[Shape]):
    for shape in shapes:
        yield shape.area()


# Context manager
class ShapeContext:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass
