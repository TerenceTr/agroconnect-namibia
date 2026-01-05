# ====================================================================
# backend/utils/validators.py
# ====================================================================

from __future__ import annotations

import re
from typing import Optional, Union, Any

localPhoneRegex = re.compile(r"^(081|083|085)\d{7}$")


def validate_phone(phone: Optional[Union[str, int, Any]]) -> Optional[str]:
    if phone is None or phone == "":
        return None

    phone_str = str(phone).strip()

    if not localPhoneRegex.match(phone_str):
        raise ValueError("Phone must start with 081, 083, or 085 and contain exactly 10 digits.")

    return phone_str
