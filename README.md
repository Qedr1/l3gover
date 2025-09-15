# О сервисе
Сервис для создания  L3 оверлейных сетей. Объединяет произвольные хосты в гиперконвергентной сетевой среде в одну подсеть с прозрачной маршрутизацией. Транспорт между хостами реализован на чистом UDP.
В следующих релиах будет реализован кластеризованный контрол плейн для управления адресацией, маршрутизацией и политиками доступа.

# Iperf3  (1gbit канал)
## Send
[ ID] Interval           Transfer     Bitrate         Retr<br>
[  5]   0.00-10.00  sec  1.09 GBytes   934 Mbits/sec  177             sender<br>
[  5]   0.00-10.00  sec  1.09 GBytes   933 Mbits/sec                  receiver<br>

## bidir
[ ID][Role] Interval           Transfer     Bitrate         Retr <br>
[  5][TX-C]   0.00-256.83 sec  24.3 GBytes   813 Mbits/sec  128             sender<br>
[  7][RX-C]   0.00-256.83 sec  18.0 GBytes   604 Mbits/sec  70              receiver<br>


