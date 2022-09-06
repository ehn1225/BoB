<h1>Net Filter</h1>
syntax : netfilter-test [host]<br>
sample : netfilter-test test.gilgil.net<br>
dest port가 80번인 http request 패킷의 host를 검사하고, 매개변수와 같을 경우 패킷을 DROP
<h2>Prepare</h2>
sudo iptables -A INPUT -j NFQUEUE --queue-num 0<br>
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
