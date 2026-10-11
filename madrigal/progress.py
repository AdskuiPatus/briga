"""Прогресс и кооперативная отмена длительных операций (раздел 10 кейса).

Длительные операции показывают ход и допускают отмену; уже доступные
данные остаются доступными. Ход — метка текущего этапа со счётчиками
(«файл 2/3: demo.pcapng»); отмена кооперативная: операция проверяет флаг
между единицами работы (файлами корпуса, сессиями записи) и завершается
явно через CancelledError, ничего не доделывая наполовину.

Использование:
    CLI   — Progress печатает ход в stderr, Ctrl+C отменяет;
    API   — задачи (jobs) держат Progress и отдают ход через поллинг.
"""

from __future__ import annotations

import sys
import threading
import time
from typing import Callable, Optional, TextIO


class CancelledError(Exception):
    """Операция отменена пользователем (явно, без недоделанных результатов)."""


class Progress:
    """Текущий ход операции и общий флаг отмены.

    Потокобезопасен: отмена ставится из другого потока (HTTP-запрос),
    ход читается поллингом. update_callback вызывается на каждое
    изменение (задачи API передают его в веб-слой).
    """

    def __init__(self,
                 cancel_event: Optional[threading.Event] = None,
                 update_callback: Optional[Callable[[], None]] = None):
        self.cancel_event = cancel_event or threading.Event()
        self._update = update_callback
        self._lock = threading.Lock()
        self.label = ""
        self.current = 0
        self.total = 0
        self.updated_at = time.time()

    # ---- ход ----

    def start_stage(self, label: str, total: int = 0) -> None:
        """Начать этап: метка и общее число единиц работы (0 — неизвестно)."""
        self.check_cancel()
        with self._lock:
            self.label = label
            self.total = total
            self.current = 0
            self.updated_at = time.time()
        self._notify()

    def advance(self, n: int = 1, note: str = "") -> None:
        """Отметить завершённые единицы работы; note заменяет метку."""
        self.check_cancel()
        with self._lock:
            self.current += n
            if note:
                self.label = note
            self.updated_at = time.time()
        self._notify()

    def note(self, text: str) -> None:
        """Сменить метку, не трогая счётчики (подэтап внутри единицы)."""
        with self._lock:
            self.label = text
            self.updated_at = time.time()
        self._notify()

    # ---- отмена ----

    def check_cancel(self) -> None:
        if self.cancel_event.is_set():
            raise CancelledError("операция отменена")

    def cancel(self) -> None:
        self.cancel_event.set()

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    # ---- состояние ----

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "label": self.label,
                "current": self.current,
                "total": self.total,
                "cancelled": self.cancelled,
            }

    def _notify(self) -> None:
        if self._update is not None:
            self._update()


class StderrProgress(Progress):
    """Печатает ход в поток (CLI → stderr).

    Строка печатается при смене этапа и по каждой завершённой единице,
    если этап мал; на больших этапах — раз в 5% или 1000 единиц, чтобы
    не засорять консоль. Вывод в stderr не мешает машиночитаемому stdout.
    """

    def __init__(self, stream: Optional[TextIO] = None, quiet: bool = False,
                 cancel_event: Optional[threading.Event] = None):
        super().__init__(cancel_event=cancel_event)
        self.stream = stream if stream is not None else sys.stderr
        self.quiet = quiet
        self._next_mark = 1
        self._pct_step = 0

    def start_stage(self, label: str, total: int = 0) -> None:
        super().start_stage(label, total)
        self._next_mark = 1
        self._pct_step = max(1, total // 20) if total else 0
        self._emit(f"{label}: 0/{total or '?'}")

    def advance(self, n: int = 1, note: str = "") -> None:
        super().advance(n, note)
        if not self.total or self.current >= self._next_mark \
                or self.current == self.total:
            self._emit(f"{self.label or 'этап'}: {self.current}/"
                       f"{self.total or '?'}")
            step = self._pct_step or 1
            self._next_mark = self.current + step

    def _emit(self, line: str) -> None:
        if self.quiet:
            return
        print(f"  {line}", file=self.stream, flush=True)
