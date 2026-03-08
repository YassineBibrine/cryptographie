import random
from math import gcd, isqrt, log2
from typing import Dict, List, Tuple


def fermat_test(n: int, rounds: int = 5, seed: int = 42) -> Tuple[bool, List[Dict[str, str]]]:
    steps: List[Dict[str, str]] = []

    if n < 2:
        steps.append({"round": "init", "details": "n < 2 => composite"})
        return False, steps
    if n in (2, 3):
        steps.append({"round": "init", "details": "2 and 3 are prime"})
        return True, steps
    if n % 2 == 0:
        steps.append({"round": "init", "details": "n is even => composite"})
        return False, steps

    rng = random.Random(seed)

    for i in range(1, rounds + 1):
        a = rng.randrange(2, n - 1)
        value = pow(a, n - 1, n)
        passed = value == 1
        steps.append(
            {
                "round": str(i),
                "base": str(a),
                "a^(n-1) mod n": str(value),
                "result": "pass" if passed else "composite witness",
            }
        )

        if not passed:
            return False, steps

    return True, steps


def miller_rabin_test(n: int, rounds: int = 5, seed: int = 42) -> Tuple[bool, List[Dict[str, str]]]:
    steps: List[Dict[str, str]] = []

    if n < 2:
        steps.append({"round": "init", "details": "n < 2 => composite"})
        return False, steps
    if n in (2, 3):
        steps.append({"round": "init", "details": "2 and 3 are prime"})
        return True, steps
    if n % 2 == 0:
        steps.append({"round": "init", "details": "n is even => composite"})
        return False, steps

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    steps.append({"round": "init", "details": f"n-1 = 2^{s} * {d}"})

    rng = random.Random(seed)

    for i in range(1, rounds + 1):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)

        if x in (1, n - 1):
            steps.append(
                {
                    "round": str(i),
                    "base": str(a),
                    "x0 = a^d mod n": str(x),
                    "result": "pass",
                }
            )
            continue

        passed = False
        current = x
        for _ in range(1, s):
            current = pow(current, 2, n)
            if current == n - 1:
                passed = True
                break

        steps.append(
            {
                "round": str(i),
                "base": str(a),
                "x0 = a^d mod n": str(x),
                "result": "pass" if passed else "composite witness",
            }
        )

        if not passed:
            return False, steps

    return True, steps


def _jacobi_symbol(a: int, n: int) -> int:
    if n <= 0 or n % 2 == 0:
        raise ValueError("n must be a positive odd integer")

    a %= n
    result = 1

    while a != 0:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result

        a, n = n, a

        if a % 4 == 3 and n % 4 == 3:
            result = -result

        a %= n

    return result if n == 1 else 0


def solovay_strassen_test(n: int, rounds: int = 5, seed: int = 42) -> Tuple[bool, List[Dict[str, str]]]:
    steps: List[Dict[str, str]] = []

    if n < 2:
        steps.append({"round": "init", "details": "n < 2 => composite"})
        return False, steps
    if n in (2, 3):
        steps.append({"round": "init", "details": "2 and 3 are prime"})
        return True, steps
    if n % 2 == 0:
        steps.append({"round": "init", "details": "n is even => composite"})
        return False, steps

    rng = random.Random(seed)

    for i in range(1, rounds + 1):
        a = rng.randrange(2, n - 1)
        g = gcd(a, n)

        if g > 1:
            steps.append(
                {
                    "round": str(i),
                    "base": str(a),
                    "gcd(a, n)": str(g),
                    "result": "composite witness",
                }
            )
            return False, steps

        jacobi = _jacobi_symbol(a, n)
        lhs = pow(a, (n - 1) // 2, n)
        rhs = jacobi % n
        passed = lhs == rhs

        steps.append(
            {
                "round": str(i),
                "base": str(a),
                "Euler lhs": str(lhs),
                "Jacobi rhs": str(rhs),
                "result": "pass" if passed else "composite witness",
            }
        )

        if not passed:
            return False, steps

    return True, steps


def _is_perfect_power(n: int) -> bool:
    max_b = int(log2(n)) + 1
    for b in range(2, max_b + 1):
        lo, hi = 2, int(round(n ** (1 / b))) + 2
        while lo <= hi:
            mid = (lo + hi) // 2
            val = mid**b
            if val == n:
                return True
            if val < n:
                lo = mid + 1
            else:
                hi = mid - 1
    return False


def _multiplicative_order(n: int, r: int) -> int:
    if gcd(n, r) != 1:
        return 0

    value = n % r
    k = 1
    while value != 1:
        value = (value * n) % r
        k += 1
        if k > r:
            return 0
    return k


def _phi(x: int) -> int:
    result = x
    p = 2
    n = x

    while p * p <= n:
        if n % p == 0:
            while n % p == 0:
                n //= p
            result -= result // p
        p += 1

    if n > 1:
        result -= result // n

    return result


def _poly_mul_mod(poly1: List[int], poly2: List[int], r: int, mod: int) -> List[int]:
    out = [0] * r

    for i, c1 in enumerate(poly1):
        if c1 == 0:
            continue
        for j, c2 in enumerate(poly2):
            if c2 == 0:
                continue
            out[(i + j) % r] = (out[(i + j) % r] + c1 * c2) % mod

    return out


def _poly_pow_mod(base: List[int], exp: int, r: int, mod: int) -> List[int]:
    result = [0] * r
    result[0] = 1

    power = base[:]
    e = exp

    while e > 0:
        if e & 1:
            result = _poly_mul_mod(result, power, r, mod)
        power = _poly_mul_mod(power, power, r, mod)
        e >>= 1

    return result


def aks_test(n: int) -> Tuple[bool, List[Dict[str, str]]]:
    steps: List[Dict[str, str]] = []

    if n < 2:
        steps.append({"step": "1", "details": "n < 2 => composite"})
        return False, steps
    if n in (2, 3):
        steps.append({"step": "1", "details": "2 and 3 are prime"})
        return True, steps

    if _is_perfect_power(n):
        steps.append({"step": "1", "details": "n is a perfect power => composite"})
        return False, steps

    log_n_sq = int(log2(n) ** 2)
    r = 2
    while True:
        order = _multiplicative_order(n, r)
        if order > log_n_sq:
            break
        r += 1

    steps.append({"step": "2", "details": f"Found r = {r} with ord_r(n) > log2(n)^2"})

    for a in range(2, min(r + 1, n)):
        g = gcd(a, n)
        if 1 < g < n:
            steps.append({"step": "3", "details": f"gcd({a}, {n}) = {g} => composite"})
            return False, steps

    steps.append({"step": "3", "details": "No non-trivial gcd found"})

    if n <= r:
        steps.append({"step": "4", "details": "n <= r => prime"})
        return True, steps

    limit = int(((_phi(r)) ** 0.5) * log2(n))
    limit = max(limit, 1)
    steps.append({"step": "5", "details": f"Polynomial checks up to a = {limit}"})

    for a in range(1, limit + 1):
        base = [0] * r
        base[0] = a % n
        base[1 % r] = 1

        lhs = _poly_pow_mod(base, n, r, n)
        rhs = [0] * r
        rhs[0] = a % n
        rhs[n % r] = (rhs[n % r] + 1) % n

        if lhs != rhs:
            steps.append(
                {
                    "step": "6",
                    "details": f"Failed congruence for a = {a} => composite",
                }
            )
            return False, steps

    steps.append({"step": "6", "details": "All congruences passed => prime"})
    return True, steps
