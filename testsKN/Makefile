EXEC = ../dns-monitor

DIG4OUT=DIG4out.txt
DIG6OUT=DIG6out.txt

PCAP4=pcap4.pcap
PCAP6=pcap6.pcap

EXEC_TRIM=trimExec.sh
DIG_TRIM=trimDig.sh
GEN=GEN.sh
DIG=DIG.sh
GET_META=GetMeta.sh

setup:
	sudo apt install -y tshark tcpdump
	sudo chmod +x $(GEN) $(DIG) $(GET_META) $(EXEC_TRIM) $(DIG_TRIM)

$(PCAP4): setup
	sudo ./$(GEN) $(PCAP4) $(DIG) $(DIG4OUT) 4

$(PCAP6): setup
	-nmcli connection up "FIT"
	sudo ./$(GEN) $(PCAP6) $(DIG) $(DIG6OUT) 6
	-nmcli connection down "FIT"

test: setup $(EXEC)
	-bash -c 'diff <($(EXEC)    -p $(PCAP4)                ) <(./$(GET_META) $(PCAP4))'
	-bash -c 'diff <($(EXEC)    -p $(PCAP6)                ) <(./$(GET_META) $(PCAP6))'
	-bash -c 'diff <($(EXEC) -v -p $(PCAP4) | ./$(DIG_TRIM)) <(./$(GET_META) $(PCAP4) -v)'
	-bash -c 'diff <($(EXEC) -v -p $(PCAP6) | ./$(DIG_TRIM)) <(./$(GET_META) $(PCAP6) -v)'
	-sudo            $(EXEC) -v -p $(PCAP4) | ./$(EXEC_TRIM) | diff - $(DIG4OUT)
	-sudo 			 $(EXEC) -v -p $(PCAP6) | ./$(EXEC_TRIM) | diff - $(DIG6OUT)
