# ARP Resolver

## Uvod
U savremenim mrežama, komunikacija između uređaja zasniva se na složenom skupu protokola koji omogućavaju pouzdanu razmjenu podataka. Jedan od osnovnih protokola u okviru mrežnog sloja je ARP (*engl. Address Resolution Protocol*), čija je osnovna funkcija povezivanje logičkih IP (*engl. Internet Protocol*) adresa sa fizičkim MAC (*engl. Media Access Control*) adresama. Bez ovog protokola, uređaji unutar lokalne mreže ne bi mogli efikasno komunicirati, jer bi nedostajala veza između apstraktnog adresiranja i stvarne hardverske identifikacije. ARP se koristi u gotovo svim Ethernet okruženjima i predstavlja temeljnu komponentu mrežne infrastrukture [1].

## ARP protokol i scenariji razmjene poruka
U Ethernet mrežama svaki put kada host ili ruter treba enkapsulirati IP paket u okvir, poznata je IP adresa sljedećeg uređaja, ali ne i njegova MAC adresa. Da bi se uspostavila komunikacija, koristi se ARP, koji omogućava dinamičko povezivanje IP adrese sa odgovarajućom MAC adresom [1].

Prema Odomu [2], ARP protokol se temelji na razmjeni dvije osnovne poruke:
  - **ARP Request** – poruka kojom jedan host na istoj podatkovnoj vezi traži informaciju o hardverskoj adresi drugog hosta. U poruci se obično navodi poznata ciljna IP adresa, dok je polje za ciljnu hardversku adresu postavljeno na nule. Time se od hosta s navedenom IP adresom traži da u svom ARP Reply odgovoru otkrije vlastitu hardversku (Ethernet) adresu.  
  - **ARP Reply** – poruka kojom uređaj odgovara na prethodno primljeni ARP zahtjev. U njoj se nalaze podaci o hardverskoj (Ethernet) adresi i IP adresi samog pošiljatelja, zapisani u poljima za izvorni hardver i izvornu IP adresu.   

ARP koristi vrlo jednostavnu strukturu poruke koja može da sadrži zahtjev ili odgovor za rezoluciju adrese. Ove poruke se prenose na sloju podatkovne veze (data link layer) kao sirovi sadržaj paketa. Kada se koristi Ethernet, vrijednost 0x0806 u polju EtherType označava da je riječ o ARP okviru. Dužina ARP poruke zavisi od formata adresa koje se koriste na mrežnom i link sloju. U nastavku prikazana je slika 1 na kojoj je predstavljen jedan ARP paket, te su navedene funkcionalnosti svih polja koja sačinjavaju taj paket. Vrijednosti ARP parametara su standardizovane i održava ih IANA (*engl. Internet Assigned Numbers Authority*) [3].

<div align="center">
  <img src="Graficki_prikaz/ARP_packet.png" alt="ARP_packet" title="ARP_packet">
  <p><b>Slika 1:</b> Struktura ARP poruke [3]</p>
</div>



- **Hardware Type (HTYPE)**: 16 bita Ovo polje određuje tip protokola mrežne veze. U ovom primjeru, vrijednost 1 označava Ethernet.
- **Protocol Type (PTYPE)**: 16 bita Ovo polje određuje internetwork protokol za koji je ARP zahtjev namijenjen. Za IPv4, vrijednost je 0x0800. Dozvoljene vrijednosti PTYPE dijele isti prostor numeriranja kao i EtherType.
- **Hardware Length (HLEN)**: 8 bita Dužina (u oktetima) hardverske adrese. Za Ethernet, dužina adrese je 6.
- **Protocol Length (PLEN)**: 8 bita Dužina (u oktetima) internetwork adrese. Internetwork protokol je određen u PTYPE. U ovom primjeru: IPv4 adresa ima dužinu 4.
- **Operation (OPER)**: 16 bita Određuje operaciju koju pošiljalac izvodi: 1 za zahtjev, 2 za odgovor.
- **Sender Hardware Address (SHA)**: 48 bita Medijska adresa pošiljaoca. U ARP zahtjevu ovo polje označava adresu hosta koji šalje zahtjev. U ARP odgovoru ovo polje označava adresu hosta koji je tražen.
- **Sender Protocol Address (SPA)**: 32 bita Internetwork adresa pošiljaoca.
- **Target Hardware Address (THA)**: 48 bita Medijska adresa namijenjenog primaoca. U ARP zahtjevu ovo polje se zanemaruje. U ARP odgovoru ovo polje označava adresu hosta koji je inicirao ARP zahtjev.
- **Target Protocol Address (TPA)**: 32 bita Internetwork adresa namijenjenog primaoca [3].

Prilikom razmjene ARP Request i ARP Reply poruka, polja poput HTYPE, PTYPE, HLEN i PLEN ostaju nepromijenjena, jer uvijek opisuju tip mreže i veličinu adresa.

U ARP Requestu popunjena su polja sa hardverskom i protokolskom adresom pošiljaoca (SHA i SPA), dok je polje ciljne hardverske adrese (THA) prazno ili ignorisano (najčesće se pišu nule u to polje), a ciljana protokolska adresa (TPA) sadrži IP adresu uređaja čija se MAC adresa traži. Također, OPER polje ima vrijednost 1.

U ARP Replyu uređaj koji odgovara prvo upoređuje vrijednost SPA iz zahtjeva sa vlastitom IP adresom. Ako se podudara, generiše odgovor. U tom odgovoru, SHA i SPA polja se popunjavaju njegovom vlastitom MAC i IP adresom, dok se vrijednosti koje su došle od resolvera (inicijatora zahtjeva) smještaju u THA i TPA. Polje OPER tada dobije vrijednost 2. Na taj način se originalnom pošiljaocu vraća tražena veza između ciljne IP adrese i odgovarajuće MAC adrese. Ako se IP adresa ne podudara, uređaj jednostavno ignoriše zahtjev i ne šalje ARP Reply. Prethodno opisano predstavljeno je sekvencijskim dijagramima na slici 2 i slici 3.

<div align="center">
  <img src="Graficki_prikaz/Graficki_prikaz_scenario1.png" alt="Scenario1" title="Scenario1">
  <p><b>Slika 2:</b> Grafički prikaz uspješne rezolucije</p>
</div>

<div align="center">
  <img src="Graficki_prikaz/Graficki_prikaz_scenario2.png" alt="Scenario2" title="Scenario2">
  <p><b>Slika 3:</b> Grafički prikaz neuspješne rezolucije</p>
</div>






## Opis ulaznih i izlaznih signala modula



## Dizajn konačnog automata - FSM dijagram



## Modeliranje sklopa u VHDL-u i sinteza u Intel Quartus Prime

## Testno okruženje i verifikacija u ModelSim-u

## Zaključak 

### Smjernice za budući rad



## Literatura
[1] W. Odom, CCNA 200-301 Official Cert Guide, Volume 1, Cisco Press, sve. 1, izd. 1, str. 77-78, 2020.

[2] W. Odom, CCNA 200-301 Official Cert Guide, Volume 2, Cisco Press, sve. 2, izd. 1, str. 496, 2020.

[3] "Address Resolution Protocol" (bez dat.). u Wikipedia, the Free Encyclopedia. Dostupno: https://en.wikipedia.org/wiki/Address_Resolution_Protocol [pristupano 09.10.2025.]

[4] Avalon Interface Specification, Intel Quartus Prime Design Suite 20.1, v2022.01.24

