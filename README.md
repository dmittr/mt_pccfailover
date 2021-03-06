# mt_pccfailover
Mikrotik PCC Failover

Для корректной работы скрипта необходимо установить комментарии к маршрутам провайдеров. 

Например, если провайдер A подключен к ether1, провайдер B подключен к ether2, то нужно установить комментарии к маршрутам:

````
/ip route set 0 comment="ISP-ether1"
/ip route set 1 comment="ISP-ether2"
````

В этом случае соединения будут распределяться равномерно. 

Чтобы распределить соединения в пропорции 33% и 66% нужно установить комметарии соответственно "ISP-ether1 weight=2" и "ISP-ether2 weight=1".

По умолчанию подразумевается weight=1. Другими словами weight укащывает какое количество раз правило для интерфейса провайдера будет указано в mangle.

Если через какого-либо провайдера есть потери пакетов, то прозойдет следующий набор действий:

+ Удаляются текущие соединения с учетом routing-mark
+ Увеличивается метрика маршрута в GRT до 250
+ Выключаются интерфейсы GRE привязанные к адресу провайдера
+ Удаляются MANGLE правила

Установка

````
/tool fetch mode=https url="https://raw.githubusercontent.com/dmittr/mt_pccfailover/main/setup.script.rsc" http-method=get output=file
/import file-name=setup.script.rsc
/system script run startup_set_global_vars.script
````
