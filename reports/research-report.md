# Отчёт об исследовании: madrigal-lab

Лаборатория протоколов МАДРИГАЛ: локальный инструмент исследования недокументированного TCP-протокола по PCAP/PCAPNG — декларативные интерпретации, корпус проверки, корреляция с журналом действий, отчёты и замеры. Демо-стенд (examples/) и реальный стенд «Термостенд» (case/).

Инструмент: madrigal-lab v0.1.0; отчёт сформирован 2026-10-17T18:14:22+00:00. Манифест проекта sha256 `d108bc037d3df342…`.
Условия воспроизведения: Python >=3.12; пакеты: pyyaml>=6.0.
Настройки: overlap_policy=first-seen, directions=['a2b', 'b2a'].

## Исследованные записи

* `examples/demo.pcapng` sha256 `ba574d0da0fcccf6…` — эталонное соединение стенда
* `examples/demo_defect.pcapng` sha256 `71013a6011e6cd7c…` — дефекты захвата: midstream, пропуск, перекрытие
* `examples/demo_counterexample.pcapng` sha256 `f286cca1ab61a047…` — контрпример: ответ 99 на установку 21
* `case/recordings/research/01_configuration.pcap` sha256 `6e9019561d4ae13c…` — исследование: базовый обмен конфигурацией (2 сессии)
* `case/recordings/research/02_variations.pcapng` sha256 `ce1b47e6e471b9e6…` — исследование: вариации параметров, есть служебный probe 0x7E
* `case/recordings/research/03_combined_messages.pcap` sha256 `3590b1111504efa7…` — исследование: несколько сообщений в одном TCP-сегменте
* `case/recordings/additional/04_new_observations.pcapng` sha256 `a7ad6db37afc64d5…` — дополнительные наблюдения чтения значений и установки порога
* `case/recordings/diagnostics/01_retransmission.pcap` sha256 `f4db652ada2a19db…` — диагностика: ретрансмиссия, дедуп по seq
* `case/recordings/diagnostics/02_reordered.pcapng` sha256 `d039dd254f96c894…` — диагностика: переупорядочение сегментов, порядок по seq
* `case/recordings/diagnostics/03_missing_segment.pcap` sha256 `264e1503f162fe29…` — диагностика: пропуск сегмента, partial/unknown фиксируются
* `case/recordings/diagnostics/04_snaplen_truncated.pcapng` sha256 `de6b57e1e3d1c086…` — диагностика: усечённый захват (snaplen)
* `case/recordings/diagnostics/05_conflicting_overlap.pcap` sha256 `abee9bbd87963c26…` — диагностика: конфликтующее перекрытие, оставлен первый увиденный
* `case/recordings/diagnostics/06_missing_beginning.pcapng` sha256 `850aab35d90d265e…` — диагностика: сессия без начала (midstream)
* `case/recordings/diagnostics/07_checksum_offload.pcap` sha256 `b2c665d464ef2d53…` — диагностика: контрольные суммы offload
* `case/recordings/diagnostics/08_bad_checksum.pcapng` sha256 `53c2ad8535e1bd38…` — диагностика: некорректная контрольная сумма

## Интерпретации и основания выводов

### demo-protocol (`examples/demo-protocol.yaml`, sha256 `23ed9ecf3f06c752…`)

Область применимости: направления a2b, b2a. Распознаваемые сообщения: read_params (b2a), set_value (b2a), get_measurement (b2a), params_response (a2b), set_ack (a2b), measurement_response (a2b).

| Гипотеза | Утверждение | Основания | Статус | Проверка |
|---|---|---|---|---|
| h-echo | Ответ set_ack подтверждает установленное значение: поле value ответа равно полю value запроса set_value. | запись: действие «задать 21» → запрос value=21, ответ value=21; запись: действие «задать 37» → запрос value=37, ответ value=37 | proposed | механическая (pairs/expect) |
| h-status-zero | status=0 в ответе означает успешное выполнение запроса. | во всех ответах успешного обмена записи status=0 | proposed | не присвоена |

### thermostand (`schemas/thermostand-protocol.yaml`, sha256 `79eeadca18993d8a…`)

Область применимости: направления a2b, b2a. Распознаваемые сообщения: req_read_config (a2b), req_set_config (a2b), req_read_values (a2b), resp_read_config (b2a), resp_set_config (b2a), resp_read_values (b2a).

| Гипотеза | Утверждение | Основания | Статус | Проверка |
|---|---|---|---|---|
| h_seq_read_config | ответ read-config повторяет seq соответствующего запроса | research/01: запросы seq=01,06,09 → ответы с теми же seq | proposed | механическая (pairs/expect) |
| h_seq_set_config | ответ set-config повторяет seq запроса, в том числе отклонённого | research/02: отклонённые set-config seq=09,0B имеют ответы с тем же seq | proposed | механическая (pairs/expect) |
| h_set_config_echo | принятый set-config подтверждает установленный period (status=ok) | research/01: установка period=1000 → ответ period=1000; additional/04: установка 5000 → ответ 5000; 500 → ответ 500 | proposed | механическая (pairs/expect) |
| h_read_values_count | read-values возвращает ровно запрошенное число измерений (status=ok) | research/01: count=3 → 3 записи в ответе; diagnostics/03: count=16 → 16 записей | proposed | механическая (pairs/expect) |
| h_status_semantics | status=03 означает отклонение параметров, 02 — повреждённое тело, 04 — измерения выключены | research/02: period=99 (вне диапазона) → status=03; label с невалидным UTF-8 → status=02; research/01: enabled=false → read-values → status=04 | proposed | не присвоена |
| h_alarm_threshold | alarm=1 тогда и только тогда, когда температура ≥ threshold | research/01 (threshold 19.0): 21.25/25.0 → alarm=1, -5.5 → alarm=0; research/01 (threshold 21.0): 18.5 → alarm=0 | proposed | не присвоена |
| h_temp_encoding | temperature_c и threshold_c — знаковые целые в сотых единицах (i16 BE) | research/01: FDA0 → -5.50; research/02: FF06 → -2.50 (знаковые, дробные) | proposed | не присвоена |

## Проверенные примеры

### Корпус «demo-corpus» (схема «demo-protocol», `reports/demo-corpus-verify.json`)

Отчёт 2026-10-11T17:24:41+00:00, статус: актуален. Файлов 3: ожидания выполнены 3, с расхождениями 0.

| Сводка | нарушения | неохват | неоднозначности | неприменимые | неизвестные |
|---|---|---|---|---|---|
| Значение | 1 | 1 | 1 | 4 | 3 |

* нарушения: demo_counterexample.pcapng: гипотеза h-echo опровергнута данными: контрпримеров 1 из 2 пар; первый: set_value#0=21 против set_ack#0=99
* неохват: demo_defect.pcapng: a2b: неопознанных сообщений 2 — правилами схемы не описаны
* неоднозначности: demo_defect.pcapng: a2b: конфликтующих перекрытий 1 (оставлен первый увиденный вариант)
* неприменимые: demo.pcapng: h-status-zero: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: demo_defect.pcapng: h-echo: not_applicable — нет примеров сообщений: set_value (1), set_ack (0)
* неприменимые: demo_defect.pcapng: h-status-zero: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: demo_counterexample.pcapng: h-status-zero: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неизвестные: demo_defect.pcapng: a2b: неизвестных байтов 40 в 1 пропусках
* неизвестные: demo_defect.pcapng: a2b: частичных сообщений 1 — байты не подменяются
* неизвестные: demo_defect.pcapng: сессий без рукопожатия: 1 — начало соединения не захвачено, роли не объявляются

### Корпус «thermostand-case» (схема «thermostand», `reports/thermostand-corpus-verify.json`)

Отчёт 2026-10-17T18:12:07+00:00, статус: актуален. Файлов 12: ожидания выполнены 12, с расхождениями 0.

| Сводка | нарушения | неохват | неоднозначности | неприменимые | неизвестные |
|---|---|---|---|---|---|
| Значение | 3 | 4 | 1 | 40 | 4 |

* нарушения: recordings/diagnostics/03_missing_segment.pcap: гипотеза h_seq_read_config опровергнута данными: контрпримеров 2 из 2 пар; первый: req_read_config#0=1 против resp_read_config#1=4
* нарушения: recordings/diagnostics/03_missing_segment.pcap: гипотеза h_read_values_count опровергнута данными: контрпримеров 3 из 3 пар; первый: req_read_values#1=1 против resp_read_values#1=2
* нарушения: recordings/diagnostics/06_missing_beginning.pcapng: гипотеза h_seq_read_config опровергнута данными: контрпримеров 2 из 2 пар; первый: req_read_config#2=4 против resp_read_config#0=1
* неохват: recordings/research/02_variations.pcapng: a2b: неопознанных сообщений 1 — правилами схемы не описаны
* неохват: recordings/research/02_variations.pcapng: b2a: неопознанных сообщений 1 — правилами схемы не описаны
* неохват: recordings/diagnostics/04_snaplen_truncated.pcapng: b2a: ошибок фрейминга 1 — поток не размечен полностью
* неохват: recordings/diagnostics/06_missing_beginning.pcapng: a2b: 3 Б данных вне сообщений
* неоднозначности: recordings/diagnostics/05_conflicting_overlap.pcap: b2a: конфликтующих перекрытий 1 (оставлен первый увиденный вариант)
* неприменимые: recordings/research/01_configuration.pcap: h_status_semantics: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/research/01_configuration.pcap: h_alarm_threshold: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/research/01_configuration.pcap: h_temp_encoding: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/research/02_variations.pcapng: h_status_semantics: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/research/02_variations.pcapng: h_alarm_threshold: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/research/02_variations.pcapng: h_temp_encoding: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/research/03_combined_messages.pcap: h_status_semantics: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/research/03_combined_messages.pcap: h_alarm_threshold: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/research/03_combined_messages.pcap: h_temp_encoding: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/additional/04_new_observations.pcapng: h_status_semantics: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/additional/04_new_observations.pcapng: h_alarm_threshold: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/additional/04_new_observations.pcapng: h_temp_encoding: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/01_retransmission.pcap: h_status_semantics: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/01_retransmission.pcap: h_alarm_threshold: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/01_retransmission.pcap: h_temp_encoding: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/02_reordered.pcapng: h_status_semantics: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/02_reordered.pcapng: h_alarm_threshold: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/02_reordered.pcapng: h_temp_encoding: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/03_missing_segment.pcap: h_status_semantics: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/03_missing_segment.pcap: h_alarm_threshold: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/03_missing_segment.pcap: h_temp_encoding: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/04_snaplen_truncated.pcapng: h_seq_read_config: not_applicable — нет примеров сообщений: req_read_config (3), resp_read_config (0)
* неприменимые: recordings/diagnostics/04_snaplen_truncated.pcapng: h_seq_set_config: not_applicable — нет примеров сообщений: req_set_config (1), resp_set_config (0)
* неприменимые: recordings/diagnostics/04_snaplen_truncated.pcapng: h_set_config_echo: not_applicable — нет примеров сообщений: req_set_config (1), resp_set_config (0)
* неприменимые: recordings/diagnostics/04_snaplen_truncated.pcapng: h_read_values_count: not_applicable — нет примеров сообщений: req_read_values (4), resp_read_values (0)
* неприменимые: recordings/diagnostics/04_snaplen_truncated.pcapng: h_status_semantics: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/04_snaplen_truncated.pcapng: h_alarm_threshold: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/04_snaplen_truncated.pcapng: h_temp_encoding: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/05_conflicting_overlap.pcap: h_status_semantics: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/05_conflicting_overlap.pcap: h_alarm_threshold: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/05_conflicting_overlap.pcap: h_temp_encoding: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/06_missing_beginning.pcapng: h_status_semantics: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/06_missing_beginning.pcapng: h_alarm_threshold: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/06_missing_beginning.pcapng: h_temp_encoding: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/07_checksum_offload.pcap: h_status_semantics: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/07_checksum_offload.pcap: h_alarm_threshold: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/07_checksum_offload.pcap: h_temp_encoding: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/08_bad_checksum.pcapng: h_status_semantics: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/08_bad_checksum.pcapng: h_alarm_threshold: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неприменимые: recordings/diagnostics/08_bad_checksum.pcapng: h_temp_encoding: not_checked — нет механической проверки — утверждение остаётся предположением исследователя
* неизвестные: recordings/research/01_configuration.pcap: h_read_values_count: проверка неполная — проверка неполная: пар с неизвестными значениями: 1
* неизвестные: recordings/research/02_variations.pcapng: h_set_config_echo: проверка неполная — проверка неполная: пар с неизвестными значениями: 2
* неизвестные: recordings/diagnostics/04_snaplen_truncated.pcapng: b2a: неизвестных байтов 31 в 1 пропусках
* неизвестные: recordings/diagnostics/06_missing_beginning.pcapng: сессий без рукопожатия: 1 — начало соединения не захвачено, роли не объявляются

## Контрпримеры (опровергнутые данными гипотезы)

* Гипотеза **h-echo** («Ответ set_ack подтверждает установленное значение: поле value ответа равно полю value запроса set_value.») опровергнута: контрпримеров 1.
  * `demo_counterexample.pcapng` сессия 0: set_value#0=21 (пакеты 3) против set_ack#0=99 (пакеты 4)
* Гипотеза **h_seq_read_config** («ответ read-config повторяет seq соответствующего запроса») опровергнута: контрпримеров 2.
  * `recordings/diagnostics/03_missing_segment.pcap` сессия 0: req_read_config#0=1 (пакеты 3, 5, 7) против resp_read_config#1=4 (пакеты 22)
  * `recordings/diagnostics/03_missing_segment.pcap` сессия 0: req_read_config#3=4 (пакеты 20) против resp_read_config#4=7 (пакеты 30)
* Гипотеза **h_read_values_count** («read-values возвращает ровно запрошенное число измерений (status=ok)») опровергнута: контрпримеров 3.
  * `recordings/diagnostics/03_missing_segment.pcap` сессия 0: req_read_values#1=1 (пакеты 7) против resp_read_values#1=2 (пакеты 22)
  * `recordings/diagnostics/03_missing_segment.pcap` сессия 0: req_read_values#4=2 (пакеты 20) против resp_read_values#3=4 (пакеты 30)
  * `recordings/diagnostics/03_missing_segment.pcap` сессия 0: req_read_values#5=4 (пакеты 24, 26, 28) против resp_read_values#15=16 (пакеты 38, 40, 42, 44)
* Гипотеза **h_seq_read_config** («ответ read-config повторяет seq соответствующего запроса») опровергнута: контрпримеров 2.
  * `recordings/diagnostics/06_missing_beginning.pcapng` сессия 0: req_read_config#2=4 (пакеты 14) против resp_read_config#0=1 (пакеты 2)
  * `recordings/diagnostics/06_missing_beginning.pcapng` сессия 0: req_read_config#5=7 (пакеты 22) против resp_read_config#3=4 (пакеты 16)

## Наблюдения исследователя

* установка значения 21: запрос value=21, ответ set_ack подтверждает value=21 (основание гипотезы h-echo) (файл `examples/demo.pcapng`, сессия 0, направление a2b, смещение 9, пакеты 8, 9)
* ответ 99 на установку 21 — контрпример, опровергающий h-echo на данных (файл `examples/demo_counterexample.pcapng`, сессия 0, направление a2b, смещение 9)
* потерянный сегмент: 40 байт неизвестных между смещениями, не подменяются нулями (файл `examples/demo_defect.pcapng`, сессия 0, направление a2b)
* журнал действий ↔ обмен: 6 типов действий (чтение/запись конфигурации, чтение значений) сверены с записями research/01–03 и additional/04 — 0 противоречий (mismatch); статусы и эхо подтверждаются исходными байтами (файл `case/recordings/research/01_configuration.pcap`, сессия 0)
* неопознанный служебный probe (тип 0x7E) в research/02 — оставлен как честный неохват, не подменён известным типом (файл `case/recordings/research/02_variations.pcapng`, сессия 0)
* пропуск сегмента (diagnostics/03): гипотезы h_seq_read_config и h_read_values_count опровергнуты данными, контрпримеры привязаны к пакетам; число сообщений не завышается (файл `case/recordings/diagnostics/03_missing_segment.pcap`, сессия 0, направление b2a)
* midstream (diagnostics/06): сессия без начала не объявлена полноценной, 3 байта вне рамок зафиксированы (файл `case/recordings/diagnostics/06_missing_beginning.pcapng`, сессия 0, направление a2b)

## Ограничения области применимости

* интерпретация частичная: описаны изученные записи корпуса; неизвестные участки (неопознанные сообщения, пропуски, частичные сообщения) видимы явно и не подменяются
* совпадения на примерах корпуса не доказывают назначение поля и универсальность модели (раздел 7.1 кейса)
* перекрытия с различающимися байтами: применяется политика first-seen, альтернатива сохраняется в ambiguities с пакетами
* midstream-соединения: роли (клиент/устройство) не назначаются, направления заданы относительно канонических endpoint'ов
* поддерживаются PCAP/PCAPNG с Ethernet(+VLAN), IPv4, TCP; другие уровни явно диагностируются как неподдерживаемые

## Открытые вопросы

* гипотеза h-status-zero (статус proposed): status=0 в ответе означает успешное выполнение запроса. — механическая проверка не присвоена, предположение остаётся неподтверждённым
* гипотеза h_status_semantics (статус proposed): status=03 означает отклонение параметров, 02 — повреждённое тело, 04 — измерения выключены — механическая проверка не присвоена, предположение остаётся неподтверждённым
* гипотеза h_alarm_threshold (статус proposed): alarm=1 тогда и только тогда, когда температура ≥ threshold — механическая проверка не присвоена, предположение остаётся неподтверждённым
* гипотеза h_temp_encoding (статус proposed): temperature_c и threshold_c — знаковые целые в сотых единицах (i16 BE) — механическая проверка не присвоена, предположение остаётся неподтверждённым
* [неохват] demo_defect.pcapng: a2b: неопознанных сообщений 2 — правилами схемы не описаны
* [неоднозначности] demo_defect.pcapng: a2b: конфликтующих перекрытий 1 (оставлен первый увиденный вариант)
* [неизвестные] demo_defect.pcapng: a2b: неизвестных байтов 40 в 1 пропусках
* [неизвестные] demo_defect.pcapng: a2b: частичных сообщений 1 — байты не подменяются
* [неизвестные] demo_defect.pcapng: сессий без рукопожатия: 1 — начало соединения не захвачено, роли не объявляются
* [неохват] recordings/research/02_variations.pcapng: a2b: неопознанных сообщений 1 — правилами схемы не описаны
* [неохват] recordings/research/02_variations.pcapng: b2a: неопознанных сообщений 1 — правилами схемы не описаны
* [неохват] recordings/diagnostics/04_snaplen_truncated.pcapng: b2a: ошибок фрейминга 1 — поток не размечен полностью
* [неохват] recordings/diagnostics/06_missing_beginning.pcapng: a2b: 3 Б данных вне сообщений
* [неоднозначности] recordings/diagnostics/05_conflicting_overlap.pcap: b2a: конфликтующих перекрытий 1 (оставлен первый увиденный вариант)
* [неизвестные] recordings/research/01_configuration.pcap: h_read_values_count: проверка неполная — проверка неполная: пар с неизвестными значениями: 1
* [неизвестные] recordings/research/02_variations.pcapng: h_set_config_echo: проверка неполная — проверка неполная: пар с неизвестными значениями: 2
* [неизвестные] recordings/diagnostics/04_snaplen_truncated.pcapng: b2a: неизвестных байтов 31 в 1 пропусках
* [неизвестные] recordings/diagnostics/06_missing_beginning.pcapng: сессий без рукопожатия: 1 — начало соединения не захвачено, роли не объявляются

## Повторное применение интерпретации

Сохранённая схема (машиночитаемое представление YAML/JSON) применяется к новым записям без повторения ручной работы:

* Применить сохранённую интерпретацию к новой записи:
  ```bash
  python -m madrigal apply НОВАЯ_ЗАПИСЬ.pcapng --schema СОХРАНЁННАЯ_СХЕМА.yaml --out result.json
  ```
* Проверить интерпретацию по новому корпусу записей с ожиданиями:
  ```bash
  python -m madrigal verify НОВЫЙ_КОРПУС.yaml --schema СОХРАНЁННАЯ_СХЕМА.yaml --out report.json
  ```
* Проверить актуальность ранее сохранённого отчёта:
  ```bash
  python -m madrigal stale report.json
  ```
* Убедиться, что инструмент и схема ведут себя как при сдаче (golden-примеры: входы + ожидаемые результаты):
  ```bash
  python -m madrigal golden
  ```
* Воспроизвести отчёт по проекту (какие записи, какие проверки):
  ```bash
  python -m madrigal report .
  ```

Комплект golden-примеров (`examples/golden/`) содержит примеры входных данных и ожидаемых результатов: `python -m madrigal golden` воспроизводит их и сообщает расхождения — согласованность повторного применения проверяется механически.
