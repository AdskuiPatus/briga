"""Фоновые задачи веб-API: ход и кооперативная отмена (раздел 10 кейса).

Длительные операции (проверка корпуса, применение схемы ко всей записи)
выполняются в фоновом потоке; клиент видит ход через поллинг и может
отменить. Отмена кооперативная: задача проверяет флаг между файлами
корпуса / сессиями и завершается явно — неполный результат не выдаётся
за полный (в ответе остаётся флаг cancelled).

Задачи живут в памяти процесса: инструмент автономный и локальный,
состояние не персистится и после перезапуска сервера исчезает — это
документированное поведение, а не потеря данных (исходники не меняются).
"""

from __future__ import annotations

import threading
import traceback
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional
from uuid import uuid4

from .progress import CancelledError, Progress

# сколько задач помнить (старые закрываются вытеснением)
MAX_JOBS = 50


class Job:
    """Одна фоновая задача: статус, ход, результат или ошибка."""

    def __init__(self, kind: str, fn: Callable[[Progress], dict],
                 title: str):
        self.id = uuid4().hex[:12]
        self.kind = kind
        self.title = title
        self.fn = fn
        self.status = "queued"        # queued | running | done | failed | cancelled
        self.result: Optional[dict] = None
        self.error: Optional[str] = None
        self.created_at = datetime.now(timezone.utc) \
            .isoformat(timespec="seconds")
        self.finished_at: Optional[str] = None
        self._lock = threading.Lock()
        self._wake = threading.Event()   # поллеру: ход изменился
        self.progress = Progress(update_callback=self._wake.set)
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def cancel(self) -> None:
        """Запросить отмену: флаг ставится сразу, задача остановится
        на ближайшей проверке между единицами работы."""
        self.progress.cancel()
        self._wake.set()

    def wait_update(self, timeout: float) -> bool:
        """Ждать изменения хода (для поллинга); True — ход изменился."""
        fired = self._wake.wait(timeout)
        self._wake.clear()
        return fired

    def _finish(self, status: str) -> None:
        with self._lock:
            self.status = status
            self.finished_at = datetime.now(timezone.utc) \
                .isoformat(timespec="seconds")
        self._wake.set()

    def _run(self) -> None:
        with self._lock:
            self.status = "running"
        try:
            result = self.fn(self.progress)
            self.result = result
            self._finish("done")
        except CancelledError:
            self._finish("cancelled")
        except Exception as e:          # noqa: BLE001 — диагностика в ответе
            self.error = f"{type(e).__name__}: {e}"
            self.traceback = traceback.format_exc(limit=5)
            self._finish("failed")

    def snapshot(self, include_result: bool = True) -> dict:
        snap = {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "status": self.status,
            "progress": self.progress.snapshot(),
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "error": self.error,
        }
        if include_result:
            snap["result"] = self.result
        return snap


class JobStore:
    """Хранилище задач процесса (потокобезопасное)."""

    def __init__(self) -> None:
        self._jobs: Dict[str, Job] = {}
        self._lock = threading.Lock()

    def submit(self, kind: str, title: str,
               fn: Callable[[Progress], dict]) -> Job:
        job = Job(kind, fn, title)
        with self._lock:
            self._jobs[job.id] = job
            self._trim()
        job.start()
        return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> List[Job]:
        with self._lock:
            return sorted(self._jobs.values(),
                          key=lambda j: j.created_at, reverse=True)

    def _trim(self) -> None:
        """Вытеснять завершённые задачи сверх MAX_JOBS (running не трогать)."""
        if len(self._jobs) <= MAX_JOBS:
            return
        finished = [j for j in self._jobs.values()
                    if j.status in ("done", "failed", "cancelled")]
        finished.sort(key=lambda j: j.created_at)
        for j in finished[:len(self._jobs) - MAX_JOBS]:
            del self._jobs[j.id]
