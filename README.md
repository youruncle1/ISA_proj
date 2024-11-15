# Projekt ISA 2023/2024  
**DNS monitorovací nástroj**

**Autor**: Roman Poliačik (xpolia05)  
**Dátum vytvorenia**: 28.10.2024  

---

## Popis  
Program `dns-monitor` je nástroj napísaný v jazyku C, ktorý slúži na monitorovanie DNS komunikácie na zvolenom sieťovom rozhraní alebo zo súboru vo formáte PCAP. Poskytuje informácie o DNS správach skrátene alebo v režime verbose, umožňuje ukladať doménové mená a ich preklady na IP adresy.

**Podporované typy záznamov**:  
A, AAAA, NS, MX, SOA, CNAME, SRV.

---

## Obmedzenia  
- Podpora iba pre DNS komunikáciu cez protokol UDP a port 53.  
- Nepodporuje ďalšie typy záznamov (napr. PTR, TXT...).  
---

## Kompilácia programu

Program sa kompiluje príkazom:
```bash
make
```

## Zobrazenie nápovedy

Na zobrazenie nápovedy k programu slúži parameter `-h`:
```bash
./dns-monitor -h
```

## Príklad spustenia

Monitorovanie na sieťovom rozhraní s detailným výpisom(verbose) a ukladaním doménových mien a prekladov:
```bash
sudo ./dns-monitor -i eth0 -v -d domains.txt -t translations.txt
```

Spracovanie DNS komunikácie zo súboru PCAP:
```bash
./dns-monitor -p sample.pcap -v -d domains.txt -t translations.txt
```
## Zoznam súborov

### Zdrojové súbory:
- `dns-monitor.c`
- `argparse.c`
- `pcap_handler.c`
- `dns_utils.c`

### Hlavičkové súbory:
- `dns-monitor.h`
- `argparse.h`
- `pcap_handler.h`
- `dns_utils.h`

### Ďalšie súbory:
- `Makefile`
- `README`
- `manual.pdf`

### Testovacie súbory a skripty:
- `tests/dig/test.sh`
- `tests/dig/dns_queries.txt`
- `tests/pcap/v6.pcap`
- `tests/pcap/alltypes.pcap`

---




