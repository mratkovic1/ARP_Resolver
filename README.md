# ARP Resolver

## Uvod
U savremenim mrežama komunikacija između uređaja zasniva se na složenom skupu protokola koji omogućavaju pouzdanu razmjenu podataka. Jedan od ključnih protokola u okviru mrežnog sloja je ARP (*engl. Address Resolution Protocol*), čija je osnovna funkcija povezivanje logičkih IP adresa sa fizičkim MAC adresama. Bez ovog mehanizma, uređaji unutar lokalne mreže ne bi mogli efikasno komunicirati, jer bi nedostajala veza između apstraktnog adresiranja i stvarne hardverske identifikacije. ARP se koristi u gotovo svim Ethernet okruženjima i predstavlja temeljnu komponentu mrežne infrastrukture.

## ARP protokol i scenariji razmjene poruka
U Ethernet mrežama svaki put kada host ili ruter treba enkapsulirati IP paket u okvir, poznata je IP adresa sljedećeg uređaja, ali ne i njegova MAC adresa. Da bi se uspostavila komunikacija, koristi se ARP (*Address Resolution Protocol*), koji omogućava dinamičko povezivanje IP adrese sa odgovarajućom MAC adresom.

Protokol se zasniva na razmjeni dvije osnovne poruke:
  - ARP Request – broadcast upit kojim uređaj traži MAC adresu za poznatu IP adresu.  
  - ARP Reply – odgovor koji sadrži IP adresu i pripadajuću MAC adresu, čime se omogućava nastavak komunikacije.  

Rezultati razmjene pohranjuju se u ARP cache, pa se isti upit ne mora ponavljati pri svakoj komunikaciji. Kada zapisi isteknu, uređaji ponovo šalju ARP Request zbog osvježavanja informacija. [1] 




## Opis ulaznih i izlaznih signala modula

## Dizajn konačnog automata - FSM dijagram

## Modeliranje sklopa u VHDL-u i sinteza u Intel Quartus Prime

## Testno okruženje i verifikacija u ModelSim-u

## Zaključak 

### Smjernice za budući rad



## Literatura
[1] CCNA 200-301 Official Cert Guide, Volume 1, Chapter 3: Fundamentals of WANs and IP Routing 77,78
[2] Avalon Interface Specification, Intel Quartus Prime Design Suite 20.1, v2022.01.24

