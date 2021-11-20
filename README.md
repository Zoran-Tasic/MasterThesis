# MasterThesis
Analiza programa za šifrovanje u programu PKZIP

Apstrakt

PKZIP je program za kompresiju podataka. Pored kompresije, program PKZIP omogućuje i šifrovanje podataka. 
Algoritam šifrovanja se zasniva na internom ključu od 96 bita. 
Bez obzira što dužina ključa obezbedjuje dovoljnu zaštitu od napada metodom grube sile, ispostavlja se da slabost algoritma šifrovanja 
omogućuje napad sa poznatim parom (otvoreni tekst, šifrat). 
Ako je na raspolaganju 13 uzastopnih bajtova otvorenog teksta i odgovarajući bajtovi šifrata, napad se svodi na proveru oko 2^38 umesto 2^96 varijanti.

U radu je detaljno opisan algritam šifrovanja, a zatim je pokazano kako se ispitivanjem oko 2^38 varijanti može pronaći interni ključ. 
Iako je za dešifrovanje podataka dovoljno poznavanje internog ključa, 
na kraju je pokazano kako se na osnovu poznatog internog ključa može dobiti i lozinka koja je korišćena u procesu šifrovanja.
