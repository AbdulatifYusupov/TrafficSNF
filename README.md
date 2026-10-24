# TrafficSNF (MicroWireshark)

Легковесный сетевой сниффер пакетов в реальном времени с графическим интерфейсом на C++ и Qt 6.

## Возможности

* Перечисление и выбор доступных сетевых интерфейсов.
* Захват пакетов в отдельном рабочем потоке (без фризов интерфейса).
* Разбор заголовков на лету:
  * Layer 2: Ethernet II (MAC-адреса).
  * Layer 3: IPv4, IPv6.
  * Layer 4: TCP, UDP, ICMP (порты, базовые флаги).
* Распознавание распространенных прикладных протоколов и сервисов (DNS, mDNS, LLMNR, SSDP, HTTP, HTTPS).
* Отображение сетевого трафика через кастомную модель `QAbstractTableModel`.

## Стек технологий

* **Язык**: C++17
* **GUI**: Qt 6 (Widgets)
* **Сборка**: CMake
* **Сетевой захват**: Npcap SDK / libpcap
* **Компилятор**: MinGW-w64 (GCC 13+) / MSVC

## Требования для сборки

1. Установленный драйвер **Npcap** (в режиме совместимости с WinPcap API).
2. **Npcap SDK** (путь к SDK настраивается в `CMakeLists.txt`, по умолчанию `C:/npcap-sdk`).
3. **Qt 6** (компоненты: Core, Gui, Widgets).
4. **CMake 3.16+**.

## Сборка

```bash
git clone [https://github.com/AbdulatifYusupov/SNF.git](https://github.com/AbdulatifYusupov/SNF.git)
cd SNF
mkdir build && cd build
cmake ..
cmake --build .
