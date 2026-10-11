# Лаборатория протоколов МАДРИГАЛ — контейнер для Linux x86-64.
#
# Среда проверки кейса: Linux x86-64, 4 vCPU, 8 ГиБ RAM. Образ
# воспроизводим: версии Python и зависимостей зафиксированы (requirements.txt).
#
# Сборка:  docker build -t madrigal-lab .
# Запуск:  docker run --rm -p 8000:8000 -v "$PWD:/data" madrigal-lab
#          откроется http://127.0.0.1:8000 — записи монтируются в /data.
#
# CLI внутри контейнера:
#   docker run --rm -v "$PWD:/data" madrigal-lab info /data/capture.pcapng
#
# Автономность: основной сценарий работает офлайн; зависимости
# устанавливаются на этапе сборки, в рантайме сеть не нужна.

FROM python:3.12-slim

# детерминизм: те же версии, что в requirements.txt; без кэша и recommends
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY madrigal/ ./madrigal/
COPY examples/ ./examples/
COPY README.md .

# непривилегированный пользователь: контейнер не нуждается в root
RUN useradd --create-home --uid 10001 madrigal \
    && chown -R madrigal:madrigal /app
USER madrigal

# каталог для монтируемых исследователем записей
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8000
ENV PYTHONUNBUFFERED=1

# по умолчанию — веб-интерфейс; для CLI переопределяется точка входа
CMD ["python", "-m", "madrigal", "serve", "--host", "0.0.0.0", "--port", "8000"]
