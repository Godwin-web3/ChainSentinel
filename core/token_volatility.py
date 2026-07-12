"""
core/token_volatility.py — Collateral volatility lookup

Maps a token contract address to historical price volatility via
DefiLlama's price API. No hardcoded token lists. A token's risk
classification comes from its actual price behavior, not its name.
"""

import time
import math
import requests
from typing import Optional

_CACHE: dict = {}


def get_volatility(address: str, chain: str = "ethereum", days: int = 90) -> Optional[float]:
    """
    Returns annualized volatility (stddev of daily log returns * sqrt(365)).
    Returns None on genuine data absence. Does not cache transient
    failures — only caches a confirmed lack of price history.
    """
    key = (address.lower(), days)
    if key in _CACHE:
        return _CACHE[key]

    coin_key = f"{chain}:{address.lower()}"
    now = int(time.time())
    start = now - days * 86400

    url = f"https://coins.llama.fi/chart/{coin_key}"
    prices = None

    for attempt in range(3):
        try:
            resp = requests.get(
                url,
                params={"start": start, "span": days, "period": "1d"},
                timeout=15,
            )
            if resp.status_code == 429:
                time.sleep(5 * (attempt + 1))
                continue
            if resp.status_code != 200:
                time.sleep(2)
                continue
            data = resp.json()
            coin_data = data.get("coins", {}).get(coin_key)
            if not coin_data:
                _CACHE[key] = None
                return None
            points = coin_data.get("prices", [])
            prices = [p["price"] for p in points]
            break
        except Exception:
            time.sleep(2)
            continue

    if prices is None:
        return None  # transient failure — do not cache, retry next call

    if len(prices) < 10:
        _CACHE[key] = None
        return None

    returns = [
        math.log(prices[i] / prices[i - 1])
        for i in range(1, len(prices))
        if prices[i - 1] > 0 and prices[i] > 0
    ]
    if len(returns) < 5:
        _CACHE[key] = None
        return None

    mean = sum(returns) / len(returns)
    variance = sum((r - mean) ** 2 for r in returns) / len(returns)
    daily_vol = variance ** 0.5
    annualized = daily_vol * (365 ** 0.5)

    if annualized > 2.0:
        _CACHE[key] = None
        return None

    _CACHE[key] = annualized
    return annualized
