"""
Utils functions
"""

from typing import Callable, List, Tuple
import keccaky
import types


class PowerOfTwoError(Exception):
    def __init__(self, number):
        self.number = number
        super().__init__(
            f"Size of leafs should be a power of 2 your leafs length is: {number}"
        )


class InvalidHashFunctionError(Exception):
    """Exception raised for invalid hash function."""

    def __init__(self) -> None:
        self.message = "Must type of: (bytes, bytes) -> bytes"
        super().__init__(self.message)


def keccak(data: bytes) -> bytes:
    """
    # Hash `data: str` using keccak256
    - params `data: str`
    - return `hexadecimal: str`

    ```python
    >>> keccak("merkle")
    "326fe0d8a70ab934a7bf9d1323c6d87ee37bbe70079f82e72203b1e07c0c185c"

    >>> keccak("tree")
    "b2510336c6497719adadc7ade198c988520f3349445f074dc729df0f3c2b12ad"

    >>> keccak("bitcoin")
    "7dee6e1aa550de37364ec77e03e62ea56bf42037b8297280de9d844d88444e4d"

    >>> keccak("ethereum")
    "541111248b45b7a8dc3f5579f630e74cb01456ea6ac067d3f4d793245a255155"
    ```
    """

    return keccaky.hash_it_bytes(data)


def half(list_item: List[int]) -> Tuple[int, int]:
    """
    # Slice a `x: List[int]` in a pairs
    - params `x: List[int]`
    - return `list: List[List[int]]

    ```python
    >>> slicer([1,2,3,4])
    [[1, 2], [3, 4]]

    >>> slicer([i for i in range(10)])
    [[0, 1, 2, 3, 4], [5, 6, 7, 8, 9]]
    ```
    """

    length = len(list_item) // 2

    return (list_item[:length], list_item[length:])


def slice_in_pairs(list_item: list):
    """
    # Slice a `x: List[int]` in pairs, pairs is sublist of 2 items
    - params `x: List[int]`
    - return `list: List[List[int]]

    ```python
    >>> slicer([1,2,3,4])
    [[1, 2], [3, 4]]

    >>> slicer([i for i in range(10)])
    [[0, 1], [2, 3], [4, 5], [6, 7], [8, 9]]
    ```
    """

    return [list_item[i : i + 2] for i in range(0, len(list_item), 2)]


def validate_leafs(leafs: List[str]):
    size = len(leafs)

    if size < 2:
        raise Exception("Invalid size, need > 2")

    a = isinstance(leafs, List)
    b = all(isinstance(leaf, bytes) for leaf in leafs)
    if not (a and b):
        raise Exception("Invalid type of leafs")


def validate_hash_function(hash_function: Callable[[bytes, bytes], bytes]):
    a = isinstance(hash_function, types.FunctionType)
    b = callable(hash_function)
    try:
        c = isinstance(hash_function(bytes(), bytes()), bytes)
    except TypeError:
        c = False

    valid = a and b and c
    if not valid:
        raise InvalidHashFunctionError()


def is_power_2(number: int) -> bool:
    """
    # Verify if `x: int` is power of 2
    - params `x: int`
    - return `bool`

    ```python
    assert is_power_2(2) == True
    assert is_power_2(3) == False
    assert is_power_2(16) == True
    assert is_power_2(900) == False
    ```
    """

    left: bool = number & (number - 1) == 0
    right: bool = number != 0
    if left and right:
        return True
    else:
        return False
