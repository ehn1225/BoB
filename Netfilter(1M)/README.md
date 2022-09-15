<h1>Net Filter 1M</h1>
syntax : netfilter-test [blacklist file]<br>
sample : netfilter-test sample.txt<br>
dest port가 80번인 http request 패킷의 host를 검사하고, BlackList에 존재하는 URL 일 경우 패킷을 DROP
<h2>Prepare</h2>
sudo iptables -A INPUT -j NFQUEUE --queue-num 0<br>
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0

<h2>test set</h2>
mi.com
test.gilgil.net
nike.com

