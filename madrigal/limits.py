"""Защитные пределы контрольной нагрузки (раздел 10 кейса).

Профиль измерения (не ограничения формата протокола):

    до 100 МиБ capture-файлов, 250 000 пакетов, 1000 TCP-соединений,
    100 000 сообщений; короткие команды и переменные ответы до 64 КиБ.

Инструмент по умолчанию работает в профиле `control`: превышение
обрабатывается явно — команда завершается с кодом 6 и перечисляет
пределы, API отвечает 413 с текстом нарушения. Данные не подменяются и
не обрезаются молча. Профиль `none` снимает пределы для исследовательских
запусков сверх контрольной нагрузки (`--limits none`, поле `limits` в
API).

Отдельно защищается вывод: JSON-результат `apply` при усечении списка
сообщений (`--max-messages`) помечает `messages_truncated: true` —
усечение видно, а не скрыто.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Optional

MIB = 1 << 20
KIB = 1 << 10

PROFILE_NAMES = ("control", "none")


@dataclass(frozen=True)
class Limits:
    """Числовые пределы профиля (None — предел не задан)."""

    profile: str
    file_bytes: Optional[int] = None      # размер исходного capture-файла
    packets: Optional[int] = None         # пакетов в файле
    sessions: Optional[int] = None        # TCP-соединений
    messages: Optional[int] = None        # прикладных сообщений
    answer_bytes: Optional[int] = None    # заявленный максимум ответа

    def describe(self) -> str:
        if self.profile == "none":
            return "профиль 'none' — защитные пределы сняты"
        parts = []
        if self.file_bytes is not None:
            parts.append(f"файл <= {self.file_bytes // MIB} МиБ")
        if self.packets is not None:
            parts.append(f"пакетов <= {self.packets}")
        if self.sessions is not None:
            parts.append(f"соединений <= {self.sessions}")
        if self.messages is not None:
            parts.append(f"сообщений <= {self.messages}")
        if self.answer_bytes is not None:
            parts.append(f"ответов <= {self.answer_bytes // KIB} КиБ")
        return f"профиль '{self.profile}': " + ", ".join(parts)


# контрольная нагрузка из кейса (Linux x86-64, 4 vCPU, 8 ГиБ)
CONTROL = Limits(
    profile="control",
    file_bytes=100 * MIB,
    packets=250_000,
    sessions=1_000,
    messages=100_000,
    answer_bytes=64 * KIB,
)

UNLIMITED = Limits(profile="none")

PROFILES = {"control": CONTROL, "none": UNLIMITED}


class LimitExceeded(Exception):
    """Превышение защитного предела профиля (списком нарушений)."""

    def __init__(self, limits: Limits, violations: List[str]):
        self.limits = limits
        self.violations = violations
        super().__init__(f"превышение пределов ({limits.profile}): "
                         + "; ".join(violations))


def get_profile(name: str) -> Limits:
    if name not in PROFILES:
        raise ValueError(f"неизвестный профиль {name!r} "
                         f"(допустимы: {', '.join(PROFILE_NAMES)})")
    return PROFILES[name]


def check_capture(limits: Limits, file_bytes: Optional[int] = None,
                  packets: Optional[int] = None,
                  sessions: Optional[int] = None) -> List[str]:
    """Нарушения пределов профиля по фактам открытой записи.

    file_bytes — размер файла, packets/sessions — уже посчитанные величины
    (если None — проверка соответствующего предела пропускается).
    """
    out: List[str] = []
    if limits.file_bytes is not None and file_bytes is not None \
            and file_bytes > limits.file_bytes:
        out.append(f"размер файла {file_bytes} Б ({file_bytes / MIB:.1f} МиБ) "
                   f"превышает предел {limits.file_bytes} Б "
                   f"({limits.file_bytes // MIB} МиБ)")
    if limits.packets is not None and packets is not None \
            and packets > limits.packets:
        out.append(f"пакетов {packets} превышает предел {limits.packets}")
    if limits.sessions is not None and sessions is not None \
            and sessions > limits.sessions:
        out.append(f"TCP-соединений {sessions} превышает предел "
                   f"{limits.sessions}")
    return out


def check_messages(limits: Limits, messages: int) -> List[str]:
    """Нарушение предела по числу прикладных сообщений."""
    if limits.messages is not None and messages > limits.messages:
        return [f"прикладных сообщений {messages} превышает предел "
                f"{limits.messages}"]
    return []


def file_size(path: str) -> int:
    """Размер файла без чтения (защитная проверка до загрузки в память)."""
    return os.stat(path).st_size
