/*	Matematicki fakultet		*/
/*	Diplomski - master rad		*/
/*	smer: racunarstvo i informatika	*/
/*	Zoran Tasic			*/
/*
/*	naziv rada: Analiza algoritma 	*/
/*	za sifrovanje u programu PKZIP	*/

/*Ovaj C program iz poznate sifrovane arhive (sifrovane pomocu pkzip-a 2.04) i odredjenog broja bajtova nesifrovane
/*arhive pronalazi interni kljuc i, ako korisnik to zahteva, lozinku pomocu koje je izvrseno sifrovanje. Neophodno je 
/*znati bar 13 bajtova nesifrovane arhive jer sa manje od 13 bajtova program ne moze da izvrsi kompletan napad. U tom 
/*slucaju program daje interni kljuc, ali program jako dugo radi. Bolja je varijanta, ako je poznato vise od 13 bajtova. 
/*U tom slucaju se prvo vrsi redukcija broja kandidata (pomocu viska poznatih bajtova), a zatim se sa preostalih 13
/*bajtova vrsi napad i tada program brze daje rezultat. Program dobija 3 argumenta: prvi argument je ime sifrovane arhive,
/*drugi argument je ime odgovarajuce nesifrovane arhive, a treci argument je broj bajtova koji se cita iz nesifrovane 
/*arhive (13 ili vise). Pretpostavlja se da se u arhivama nalazi samo jedan fajl. Izlaz iz programa je interni kljuc
/*key0-key2 posle kombinacije sa dobijenom lozinkom i, ako korisnik to hoce, lozinka pomocu koje je vrseno sifrovanje*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

FILE *sifr_file;				/*sifrovana arhiva*/

FILE *nesifr_file;				/*nesifrovana zip arhiva iz koje se cita prvih argv[3] bajtova
								/*koji ce sluziti za pronalazenje interne reprezentacije key0-key2
								/*pomocu kojih se desifruje ostatak sifrovanog fajla, a moze se i 
								/*otkriti lozinka pomocu koje je izvrseno sifrovanje*/

unsigned int crc32tab[256];		/*tablice koje se koriste u sifrovanju i desifrovanju zip arhive*/
unsigned int invcrc32tab[256];

unsigned char *key3list;		/*lista vrednosti key3 koja se formira pri sifrovanju*/

unsigned short key2tab[256][64];/*matrica (velicine 256x64) u kojoj redni broj reda predstavlja mogucu
								/*vrednost key3, a u svakom redu se nalazi lista 64 vrednosti bitova
								/*na pozicijama 2-16 od key2, koji moze dati odgovarajuci key3, pomocu
								/*temp=key2|3; key3=LSB(temp*(temp^1))>>8*/

unsigned char ima_jos_key2[256][64][5]; /*trodimenzioni niz koji pokazuje koje su sve vrednosti iz key2tab
								/*povezane sa odgovarajucom kombinacijom 6 bitova u dve uzastopne 
								/*vrednosti key2i i key2iminus1. Detaljno objasnjenje u funkciji init_key2tab*/

unsigned short broj_povezanih_key2[256][64]; /*tabela vrednosti koja je povezana sa nizom ima_jos_key2
								/*takodje, detaljno objasnjena u funkciji init_key2tab*/

unsigned int key2n[0x800000];	/*niz svih mogucih "perspektivnih" vrednosti key2[n], tj. onih vrednosti
								/*koje mogu da se dobiju iz neke vrednosti key2[n-1]. Ocekuje se da ce ovih
								/*vrednosti u prvoj iteraciji biti 2^22(0x400000), ali je radi sigurnosti 
								/*ostavljeno vise mesta*/

unsigned int key2n_1[0x800000];	/*niz koji se koristi u redukciji broja mogucih vrednosti liste key2[i]
								/*Detaljno objasnjen u funkciji redukcija_key2n()*/

unsigned int broj_key2n;		/*broj elemenata liste kandidata za key2[n]*/

unsigned int broj_key2n_1;		/*broj elemenata niza key2n_1*/

unsigned int broj_listi_key2n;	/*broj potencijalnih kompletnih listi key2[2]-key2[13]*/

unsigned int *key2list;			/*lista vrednosti key2. U nju ce se ucitavati jedna po jedna moguca 
								/*varijanta za niz vrednosti key2, sve dok se ne pronadje prava 
								/*kombinacija*/

unsigned int *key1list;			/*lista potencijalnih vrednosti key1*/

unsigned int *key0list;			/*lista potencijalnih vrednosti key0. Iz nje ce se odredjvati koji je pravi niz
								/*vrednost koji ce biti rezultat rada programa*/

unsigned char random_bajtovi[12];/*11 random bajtova na pocetku sifrovane arhive i 12. bajt izveden iz 
								/*crc32 vrednosti. Koriste se za pronalazenje internog kljuca*/


unsigned int key1_sifra[7];		/*potencijalna lista vrednosti key1[i] koja se formira pri kombinovanju inicijalne 
								/*vrednosti key0, key1 i key2 sa dobijenom lozinkom*/

unsigned int key0_sifra[7];		/*potencijalna lista vrednosti key0[i] koja se formira pri kombinovanju inicijalne 
								/*vrednosti key0, key1 i key2 sa dobijenom lozinkom*/


unsigned char *sifr_podaci;		/*string u koji ce se ucitati podaci iz sifrovanog fajla*/

unsigned char *nesifr_podaci;	/*string u koji ce se ucitati podaci iz nesifrovanog fajla*/

int	nadjena_kompletna_lista;	/*indikator koji pokazuje da su pronadjene liste vrednosti key0-key2 koje se koriste
								/*prilikom sifrovanja i kao pokazatelj da treba prekinuti sa daljim ispitivanjem mogucnosti*/

unsigned char lozinka[13];		/*string koji predstavlja lozinku kojom je sifrovana arhiva. Pretpostavlja se 
								/*da lozinka nije duza od 13 karaktera.*/

int pronadjena_lozinka;			/*indikator koji pokazuje da li je pronadjena lozinka i pokazuje kad treba
								/*prestati sa daljim trazenjem*/

unsigned int duzina_lozinke;	/*promenljiva koja pokazuje koliko je dugacka potencijalna lozinka. Koristi se pri 
								/*pronalazenju lozinki duzih od 6 karaktera*/


int ucitaj4(FILE *);					/*funkcija koja ucitava int iz zadatog fajla i vraca taj procitani broj*/

short int ucitaj2(FILE *);				/*funkcija koja ucitava short int iz zadatog fajla i vraca taj procitani broj*/

void ispis2(FILE *, short int);			/*funkcija koja ispisuje zadati short int u zadati fajl*/

void ispis4(FILE *, int);				/*funkcija koja ispisuje zadati int u zadati fajl*/

unsigned int provera_fajlova(void);		/*Funkcija koja ucitava zaglavlja sifrovane i nesifrovane arhive i proverava 
										/*da li su fajlovi sadrzani u njima odgovarajuceg formata, kao i da li su u 
										/*pitanju isti fajlovi (s tom razlikom sto je fajl u jednoj arhivi sifovan, a 
										/*drugoj ne). Funkcija vraca velicinu nesifrovanog fajla*/

void initcrc(void);				  		/*funkcija koja vrsi inicijalizaciju tabela crc32tab i invcrc32tab*/

unsigned int calccrc32tab(char c);		/*funkcija koja se koristi za popunjavanje tabela crc32tab i invcrc32tab*/

void zip_crack(char *, char *, unsigned int);	/*funkcija koja pronalazi pocetne vrednosti key0-key2*/
										/*(posle kombinovanja sa dobijenom lozinkom). Kao parametre dobija string
										/*sa podacima iz sifrovane arhive, string sa odgovarajucim podacima iz 
										/*nesifrovane arhive i duzinu tih stringova*/

void pronadji_lozinku();				/*funkcija koja na osnovu poznate vrednosti internog kljuca, pronalazi
										/*lozinku kojom je vrseno sifrovanje arhive*/

void init_key2tab(void);				/*funkcija koja puni matrice key2tab i broj_povezanih_key2, kao i niz
										/*ima_jos_key2*/

void generisi_prvi_skup_key2(unsigned int);	/*funkcija koja generise sve moguce vrednosti key2[n]*/

void redukcija_key2n(unsigned int);		/*funkcija koja redukuje broj potencijalnih listi key2*/

void sortiranje(int, int);				/*funkcija koja sortira (Quicksort algoritmom) niz key2n_1*/

void formiraj_listu_key2(unsigned int);	/*funkcija koja ce formirati jednu po jednu mogucu kombinaciju
										/*za listu vrednosti key2 i iz nje ce se pozivati funkcija 
										/*za dobijanje mogucih listi key1*/

void key2_rekurzija(int i);				/*funkcija koja iz vrednosti key2[i], key3[i-1] i key2[i-1] racuna 
										/*key2[i-1] i iz nje se vrsi rekurzivni poziv za racunanje key2[i-2]*/

void formiraj_listu_key1(void);			/*iz dobijene liste vrednosti za key2 formira 2^16 mogucih 
										/*listi za key1 i formira odgovarajucu listu vrednosti LSB(key0)*/

void key1_rekurzija(unsigned int);		/*funkcija koja iz vrednosti key1[i] racuna sve moguce vrednosti key1[i-1]
										/*tako da se ona "slaze" sa vrednoscu key1[i-1] (detaljno objasnjenje 
										/*u samoj funkciji), formira LSB(key0[i]) i ako je dobijena kompletna lista
										/*key1, poziva funkciju za dobijanje liste key0*/

void formiraj_listu_key0(void);			/*iz dobijene liste vrednosti za LSB(key0list[i]) formira kompletnu listu 
										/*vrednosti za key0list i ispituje da li je potencijalna lista key0list zaista
										/*ona prava lista koja se pojavljuje prilikom sifrovanja, a ako to jeste, onda
										/*stampa odgovarajucu poruku i zaustavlja dalje pretrazivanje*/

void key1_sifra5_rekurzija(unsigned int);/*funkcija slicna funkciji key1_rekurzija, samo sto se koristi pri nalazenju
										/*kompletne liste key1_sifra, parametar pokazuje od kog elementa treba zapoceti
										/*dalje trazenje. Koristi se za nalazenje lozinke duzine 5*/

void key1_sifra6_rekurzija(unsigned int);/*funkcija slicna funkciji key1_sifra5_rekurzija. Koristi se za nalazenje 
										/*lozinke duzine 6*/

void pronadji_dugacku_lozinku(unsigned int);/*funkcija pomocu koje se dobijaju lozinke duze od 6 karaktera. Parametar
										/*pokazuje trenutnu duzinu lozinke koja se ispituje,*/

int main(int argc, char **argv)
{
	unsigned int compr_size_n;			/*velicina nesifrovanog fajla*/
	char c_s, c_n;						/*karakteri sifrovanog, tj. nesifrovanog fajla*/
	unsigned int i;						/*brojac u petljama*/
	unsigned int koliko_bajtova;		/*promenljiva koja pokazuje koliko je pozato bajtova nesifrovane arhive*/

	if(argc!=4)
	{
		printf("Neodgovarajuci broj argumenata u komandnoj liniji\n");
		exit(1);					/*Prekida se program*/
	}

	nadjena_kompletna_lista=0;		/*Postavlja se da nisu pronadjene liste vrednosti koje se koriste prilikom sifrovanja*/

	sifr_file=fopen(argv[1], "rb");	/*Otvara se sifrovani fajl; otvara se samo za citanje*/

	nesifr_file=fopen(argv[2], "rb");/*Otvara se nesifrovani fajl; otvara se samo za citanje*/

	compr_size_n = provera_fajlova();/*Poziva se funkcija koja proverava da li su arhive i fajlovi sadrzani u njima 
									/*odgovarajuceg formata*/

	sscanf(argv[3], "%d", &koliko_bajtova);/*Postavlja se broj poznatih bajtova nesifrovane arhive*/

	if(koliko_bajtova < 13 || koliko_bajtova > compr_size_n)
	{
		printf("Neodgovarajuci broj (previse ili premalo) poznatih bajtova nesifrovane arhive\n");
		return 1;					/*Ako je poznato manje od 13 bajtova nesifrovane arhive, u opstem slucaju nije moguce
									/*izvrsiti napad, pa se prekida program. Takodje ako je postavljeno da je poznato vise
									/*bajtova nego sto je velicina nesifrovanog fajla, prekida se program*/
	}

	sifr_podaci = (unsigned char *) malloc(koliko_bajtova * sizeof(unsigned char *));
	nesifr_podaci = (unsigned char *) malloc(koliko_bajtova * sizeof(unsigned char *));

	/*Cita se jedan po jedan odgovarajuci karakter iz sifrovanog i nesifrovanog fajla*/
	/*i formiraju se dva stringa*/	
	for(i=0; i<koliko_bajtova; i++)
	{
		fscanf(sifr_file, "%c", &c_s);		/*Ucitava se slovo po slovo iz sifrovanog...*/
		fscanf(nesifr_file, "%c", &c_n);	/*...i nesifrovanog fajla...*/
		sifr_podaci[i] = c_s;				/*...i formiraju se stringovi*/
		nesifr_podaci[i] = c_n;
	}

	initcrc();								/*pocetno punjenje tabela crc32tab i invcrc32tab*/

	/*Poziva se funkcija koja ce pronaci pocetne vrednosti internog kljuca: key0-key2 (pre pocetka 
	/*sifrovanja samih podataka iz arhive)*/
	zip_crack(sifr_podaci, nesifr_podaci, koliko_bajtova);

	/*Ovde se moze stati sa programom. Ali, moze se ici i dalje i saznati koja je konkretna lozinka
	/*koriscena za sifrovanje same arhive*/
	printf("Da li zelite da nastavite dalje i pronadjete lozinku kojom je sifrovana arhiva?\n");
	printf("Za nastavak pritisnite taster y, a za kraj programa bilo koji drugi taster...\n");

	fclose(sifr_file);					/*Zatvara se ulazna arhiva*/

	fclose(nesifr_file);				/*Zatvara se izlazna arhiva*/
	
	scanf("%c", &c_n);
	if(c_n=='y')						/*Ako korisnik zeli da nastavi dalje i pronadje lozinku, ulazi se u funkciju*/ 
		pronadji_lozinku();				/*za pronalazenje lozinke, a u suprotnom se zavrsava program*/

	/*Oslobadja se memorija alocirana tokom rada programa*/
	free(key2list);
	free(key1list);
	free(key0list);
	free(key3list);

	free(sifr_podaci);
	free(nesifr_podaci);

	return 0;
}

int ucitaj4(FILE * ulaz_file)
{
	int c=0,t=0;
	fscanf(ulaz_file,"%c",&c);
	t=c;	    							/*U prvom koraku se cita bajt koji ce biti bajt najmanje tezine u broju*/
	fscanf(ulaz_file,"%c",&c);
	t=((c<<8)&0xff00) | t;
	fscanf(ulaz_file,"%c",&c);
	t=((c<<16)&0xff0000) | t;
	fscanf(ulaz_file,"%c",&c);
	t=((c<<24)&0xff000000) | t;
	return t;
}

short int ucitaj2(FILE * ulaz_file)
{
	int c=0;
	short int t=0;
	fscanf(ulaz_file,"%c",&c);
	t=c;	    							/*U prvom koraku se cita bajt koji ce biti bajt najmanje tezine u broju*/
	fscanf(ulaz_file,"%c",&c);
	t=((c<<8)&0xff00) | t;
	return t;
}

void ispis2(FILE * izlaz_file, short int t)
{
	int c;
	c=t&0xff;
	fprintf(izlaz_file,"%c", c);  			/*Prvo se ispisuje bajt najmanje tezine*/
	c=(t>>8)&0xff;
	fprintf(izlaz_file,"%c", c);
}

void ispis4(FILE * izlaz_file, int t)
{
	int c;
	c=t&0xff;
	fprintf(izlaz_file,"%c", c);  			/*Prvo se ispisuje bajt najmanje tezine*/
	c=(t>>8)&0xff;
	fprintf(izlaz_file,"%c", c);
	c=(t>>16)&0xff;
	fprintf(izlaz_file,"%c", c);
	c=(t>>24)&0xff;
	fprintf(izlaz_file,"%c", c);
}

unsigned int provera_fajlova(void)
{
	/*Funkcija koja ucitava zaglavlja sifrovane i nesifrovane arhive i proverava 
	/*da li su fajlovi sadrzani u njima odgovarajuceg formata, kao i da li su u pitanju 
	/*isti fajlovi (s tom razlikom sto je fajl u jednoj arhivi sifovan, a drugoj ne)*/

	/*promenljive koje ce sluziti za proveru ispravnosti dobijenih fajlova*/
	unsigned int  sig, compr_size_s, compr_size_n, uncompr_size_s, uncompr_size_n;
	unsigned short int flags, name_len_s, name_len_n, extra_len_s, extra_len_n;
	char c_s, c_n;					/*karakteri sifrovanog, tj. nesifrovanog fajla*/
	unsigned int i;					/*brojac u petljama*/

	sig = ucitaj4(sifr_file);		/*Ucitava se signatura sifrovanog fajla*/
	if(sig!=0x4034b50)
	{	
		printf("Nije ucitana zip arhiva, nego fajl nekog drugog tipa\n");
		exit(1);
	}

	sig = ucitaj4(nesifr_file);		/*Ucitava se signatura nesifrovanog fajla*/
	if(sig!=0x4034b50)
	{	
		printf("Nije ucitana zip arhiva, nego fajl nekog drugog tipa\n");
		exit(1);
	}

	fseek(sifr_file, 2, SEEK_CUR);	/*Preskacu se 2 bajta jer nisu bitni za program*/
	fseek(nesifr_file, 2, SEEK_CUR);/*Preskacu se 2 bajta jer nisu bitni za program*/

	flags = ucitaj2(sifr_file);		/*Ucitavaju se flegovi sifrovanog fajla*/
	if((flags&0x1)!=1)
	{
		printf("Nije ucitana sifrovana arhiva, nego nesto drugo\n");
		exit(0);
	}

	flags = ucitaj2(nesifr_file);	/*Ucitavaju se flegovi nesifrovanog fajla*/
	if((flags&0x1)!=0)
	{
		printf("Nije ucitana nesifrovana arhiva, nego nesto drugo\n");
		exit(0);
	}

	fseek(sifr_file, 10, SEEK_CUR);			/*Preskace se 10 bajtova jer nisu bitni za program*/
	fseek(nesifr_file, 10, SEEK_CUR);		/*Preskace se 10 bajtova jer nisu bitni za program*/

	compr_size_s = ucitaj4(sifr_file);		/*Ucitavaju se velicine sifrovanog fajla...*/
	compr_size_n = ucitaj4(nesifr_file);	/*...i nesifrovanog fajla...*/
	if(compr_size_s!=(compr_size_n+12))		/*...i proverava se da li su odgovarajucih velicina*/
	{
		printf("Sifrovana i nesifrovana arhiva nisu odgovarajucih velicina\n");
		exit(0);
	}

	uncompr_size_s = ucitaj4(sifr_file);	/*Ucitavaju se velicine sifrovanog nekompresovanog fajla...*/
	uncompr_size_n = ucitaj4(nesifr_file);	/*...i nesifrovanog nekompresovanog fajla...*/
	if(uncompr_size_s!=uncompr_size_n)		/*...i proverava se da li su odgovarajucih velicina*/
	{
		printf("Sifrovana i nesifrovana arhiva nisu odgovarajucih velicina\n");
		exit(0);
	}

	name_len_s = ucitaj2(sifr_file);		/*Ucitava se duzina naziva sifrovanog fajla*/
	name_len_n = ucitaj2(nesifr_file);		/*Ucitava se duzina naziva nesifrovanog fajla*/
	if(name_len_s != name_len_n)
	{
		printf("Fajlovi koji se nalaze u sifrovanoj i nesifrovanoj arhiva nemaju ime iste duzine\n");
		exit(0);
	}

	extra_len_s = ucitaj2(sifr_file);		/*Ucitava se duzina extra_field sifrovanog fajla*/
	extra_len_n = ucitaj2(nesifr_file);		/*Ucitava se duzina extra_field nesifrovanog fajla*/
	if(extra_len_s != extra_len_n)
	{
		printf("Sifrovana i nesifrovana arhiva nemaju istu duzinu polja extra_field\n");
		exit(0);
	}

	if(name_len_s > 0)
	{
		for(i=name_len_s;i>0;i--)			/*Citaju se imena arhiviranih fajlova u sifrovanoj i*/
		{									/*nesifrovanoj arhivi i uporedjuju se*/
			fscanf(sifr_file, "%c", &c_s);
			fscanf(nesifr_file, "%c", &c_n);
			if(c_s != c_n)
			{
				printf("Fajlovi koji se nalaze u sifrovanoj i nesifrovanoj arhiva nemaju isto ime\n");
				exit(0);
			}
		}
	}

	if(extra_len_s>0)
	{
		for(i=extra_len_s;i>0;i--)			/*Citaju se extra field polja (ako ih ima)*/
		{									/*i uporedjuju se*/
			fscanf(sifr_file, "%c", &c_s);
			fscanf(nesifr_file, "%c", &c_n);
			if(c_s != c_n)
			{
				printf("Sifrovana i nesifrovana arhiva nemaju isto polje extra field\n");
				exit(0);
			}

		}
	}
	
	/*Ucitavaju se 12 bajtova sa pocetka sifrovane arhive koji predstavljaju 11 random bajtova i 12. bajt 
	/*koji predstavlja MSB(crc32 value) datog fajla*/
	for(i=0; i<12; i++)
	{
		fscanf(sifr_file, "%c", &c_s);
		random_bajtovi[i]=c_s;
	}

	return compr_size_n;

}

void zip_crack(char *sifr_podaci, char *nesifr_podaci, unsigned int len)
{
	unsigned int i;			/*brojac u petljama*/

	init_key2tab();			/*Inicijalizuju se tabele key2tab, broj_povezanih_key2 i 3D niz ima_jos_key2*/
	printf("Inicijalizuju se tabele neophodne za rad programa...\n");

	/*Inicijalizuju se lista key3list, key2list, key1list i key0list*/
	key3list = (unsigned char *)malloc(len*sizeof(unsigned char *));
	key2list = (unsigned int *)malloc(13*sizeof(unsigned int *));
	key1list = (unsigned int *)malloc(13*sizeof(unsigned int *));
	key0list = (unsigned int *)malloc(13*sizeof(unsigned int *));

	if(key3list==NULL || key2list==NULL || key1list==NULL || key0list==NULL)
		printf("Nije rezervisano dovoljno memorije\n");

	for(i=0; i<len; i++)		/*U svakom ciklusu petlje se uzima jedan karakter iz sifrovanog i jedan karakter
								/*iz nesifrovanog stringa. Ciklusa ima onoliko, kolika je duzina dobijenih stringova*/
	{
		key3list[i]=sifr_podaci[i]^nesifr_podaci[i];	/*Dobija se lista vrednosti key3 koja se koristi pri sifrovanju*/
	}

	generisi_prvi_skup_key2(len-1);		/*Poziva se funkcija koja formira skup svih "perspektivnih" vrednosti key2[n]
										/*tj. svih onih vrednosti koje mogu biti dobijene od neke vrednosti key2[n-1]*/

	printf("Vrsi se redukcija broja potencijalnih listi vrednosti key2[i]...\n");
	for(i=(len-1); i>=13; i--)
		redukcija_key2n(i);		/*Poziva se funkcija koja redukuje broj potencijalnih listi key2*/

	printf("Zavrsena redukcija. Preostalo je %d mogucnosti za key2[12]\n", broj_key2n);
	printf("Prelazi se na ispitivanje jedne po jedne moguce liste vrednosti za key2[i]...\n");

	broj_listi_key2n=0;			/*Broj pronadjenih potencijalnih kompletnih listi key2[2]-key2[n] se postavlja na nulu*/
	
	for(i=0; i<broj_key2n; i++)
	{	
		/*Ispituje se da li su pronadjene liste vrednosti kompletne key0-key2 koje se zaista koriste prilikom 
		/*sifrovanja. Ako to jeste slucaj, obustavlja se dalje trazenje*/
		if(nadjena_kompletna_lista==1)
			return;

		/*U svakoj iteraciji se poziva funkcija koja ce dati jednu po jednu kompletnu potencijalnu listu vrednosti 
		/*key2[i], 2<i<13*/
		formiraj_listu_key2(key2n[i]);
		
		/*Ispisuje se informacija o napredovanju programa. Na svakih 5 ispitanih mogucih listi za key2[i], ispisuje se
		/*poruka o procentu ispitanih mogucnosti u odnosu na ukupan broj kandidata za listu vrednosti key2[i].
		/*Ova informacija nece biti bas precizna, jer se ne zna unapred koliko postoji potencijalnih listi vrednosti 
		/*za key2[i]. Ali, zna se da broj potencijalnih vrednosti nece mnogo da odstupa od broj_key2n (broja mogucih
		/*kombinacija za key2[13], koji je dobijen posle redukcije). Testiranjem je pokazano da odstupanje, u principu.
		/*ne prelazi 10-15%.*/
		if((i%5) == 0)
			printf("Ispitano %.2f%% ukupnog broja kombinacija\n", ((float)i/broj_key2n)*100);
	}
}

void initcrc(void)							/*Pocetno punjenje tabela crc32tab i invcrc32tab*/
{
	unsigned int val;
	int i;

	for (i=0 ; i<256 ; i++)
	{
	val = calccrc32tab((char) i);
	crc32tab[i]=val;
	invcrc32tab[(int)(val>>0x18)] = (val<<8) ^ i;
	}
}

unsigned int calccrc32tab(char c)			/*Funkcija za izracunavanje vrednosti crctab i invcrctab*/
{
	unsigned int val = c&0xff;
	int i;
	for (i=0 ; i<8 ; i++)
	{
	if (val&1)
		val = (val>>1)^0xEDB88320uL;
	else
		val = (val>>1);
	}
	return (val);
}

void init_key2tab(void)
{
	int i, j, k;			/*brojaci u petlji*/
	int len[256];			/*niz koji pokazuje koliko je odgovarajucih vrednosti bitova 2-15 vec povezano sa 
							/*konkretnom vrednoscu key3*/
	unsigned int key3;
	unsigned short value;	/*promenljiva koja ce uzimati sve moguce vrednosti od 0 do 256*64; sluzi da 
							/*se proveri koja vrednost odgovara kom key3*/
	unsigned int pom;		/*pomocna promenljiva koja se koristi za razna izracunavanja*/

	for(i=0; i<256; i++)
		len[i]=0;			/*Za svaki moguci key3 se postavlja broj odgovarajucih vrednosti bitova 2-15 na 0*/

	pom=0;
	for(value=0; value < 256*64; value++)	/*Uzimaju se sve moguce vrednosti za bitove 2-15. vrednosti key2*/
	{										/*i proverava se koju vrednost key3 oni daju*/
		pom = value<<2;		/*Podesava se da se data vrednost nalazi na bitovima 2-15*/
		pom = pom|3;		/*Bitovi 0 i 1 se postavljaju na jedinice*/
		key3 = pom*(pom^1);
		key3 = (key3>>8);
		key3 = key3 & 0xff;	/*Dobili smo key3 koji daje konkretna vrednost value.*/

		pom=value<<2;		/*Podesava se da se value nalazi na pozicijama 2-15...*/
		pom=pom&0xfffc;		/*...a da se na pozicijama 0 i 1 nalaze nule*/

		key2tab[key3][len[key3]] = pom;/*Postavlja se promenljiva value u listu vrednosti koje daju*/
							/*konkretan key3*/

		len[key3]++;		/*Broj onih pronadjenih vrednosti koje daju konkretan key3 
							/*se povecava za 1*/
	}

	/*Prelazi se na inicijalizaciju trodimenzionog niza ima_jos_key2 i tabele broj_povezanih_key2*/

	/*Objasnjenje trodimenzionog niza ima_jos_key2[red_key3][koji_bitovi][koliko_ima]:*/

	/*Vrednosti key2[i] i key2[i-1] su povezane formulom: 
	/*key2[i-1] = (key2[i]<<8) xor invcrc32tab[MSB(key2[i])] xor MSB(key1[i]).
	/*U teorijskom delu ovog rada (poglavlje 3.1) je pokazano da su bitovi na pozicijama 10-15 leve i desne
	/*strane jednakosti isti. Na osnovu tih 6 bitova, iz vrednosti key2[i], mozemo dobiti potencijalnog 
	/*kandidata za key2[i-1], ali nazalost ne jedinstvenog kandidata. Upravo za to sluzi trodimenzioni niz 
	/*ima_jos_key2: on daje sve moguce kandidate iz tabele key2tab koji se nalaze u redu red_key3, a bitovi 
	/*na pozicijama 10-15 su isti kao koji_bitovi. Treca dimenzija (koliko_ima) ovog niza pokazuje koliko 
	/*takvih kandidata postoji. Testiranjem programa, zakljuceno je da ovakvih kandidata niukom slucaju nema 
	/*vise od 5. 
	/*Vrednosti ovog niza su redni brojevi elemenata tabele key2tab (iz vrste red_key3) koji imaju iste 
	/*vrednosti bitova 10-15 kao (key2[i]<<8) xor invcrc32tab[MSB(key2[i])] xor MSB(key1[i]).
	
	/*Tabela broj_povezanih_key2[key3][bitovi] pokazuje koliko ima vrednosti (razlicitih od nule) u nizu
	/*ima_jos_key2[key3][bitovi]*/

	/*Postavljaju se pocetne vrednosti na nulu*/
	for(i=0; i<256; i++)
		for(j=0; j<64; j++)
		{
			broj_povezanih_key2[i][j]=0;
			for(k=0; k<5; k++)
				ima_jos_key2[i][j][k]=0;
		}

	for(key3=0; key3<256; key3++)
		for(pom=0; pom<64; pom++)
		{
		/*ima_jos_key2[key3][(drugaVrednostKey2>>10)&63] se koristi za nalazenje svih k tako da je
		/*key2tab[key3][k] & 0xfc00 == drugaVrednostKey2 & 0xfc00*/
		ima_jos_key2[key3][(key2tab[key3][pom]>>0xa) & 0x3f][broj_povezanih_key2[key3][(key2tab[key3][pom]>>0xa)&0x3f]]=pom;
		broj_povezanih_key2[key3][(key2tab[key3][pom]>>0xa)&0x3f]++;
		}
}

void generisi_prvi_skup_key2(unsigned int n)
{
	/*Funkcija uzima vrednosti key3[n] i key3[n-1] i formira listu "perspektivnih" vrednosti key2[n], tj. onih
	/*vrednosti koje mogu da se dobiju od neke vrednosti key2[n-1]. Ostale vrednosti se odbacuju.*/

	int i, j, k;				/*brojaci u petljama*/
	unsigned int prvi_key2;		/*key2[n]*/
	unsigned int drugi_key2;	/*key2[n-1]*/
	unsigned short bitovi_6;	/*bitovi na pozicijama 10-15 koji treba da se poklapaju prilikom odredjenih
								/*izracunavanja u uzastopnim iteracijama*/
	unsigned short bitovi_2;	/*bitovi na pozicijama 0 i 1*/
	
	printf("Generise se prvi skup potencijalnih vrednosti key2[n]...\n");

	broj_key2n=0;				/*Broj elemenata liste key2n se postavlja na nulu*/

	for(i=0; i<64; i++)
	{
		for(j=0; j<0x10000; j++)
		{
			prvi_key2 = key2tab[key3list[n]][i];/*Uzimaju se sve 64 mogucnosti za bitove 2-15 iz tabele key2tab...*/
			prvi_key2 += (j<<16);			/*...i dodaju mu se sve moguce (2^16) vrednosti za bitove 16-31...*/	
											/*...tako da je dobijena moguca vrednost key2[n]. Sada ostaje samo 
											/*da se proveri da li je ona "perspektivna".*/

			/*Prethodna vrednost key2[n-1] se dobija pomocu formule
			/*key2[n-1]=(key2[n]<<8) xor invcrc32tab[MSB(key2[n])] xor MSB(key1[n]).
			/*Posto ce nama trebati samo bitovi na poziciji 10-15 uzeli smo da je 
			/*MSB(key1[n])=0 jer ne utice na bitove (10-15) koji treba da se dobiju*/
			drugi_key2 = (prvi_key2<<8)^invcrc32tab[prvi_key2>>0x18]^0x00;

			bitovi_6=drugi_key2 & 0xfc00;	/*Bitovi na pozicijama 0-9, kao i 16-31 se postavljaju na 0 jer 
											/*nisu bitni za slaganje vrednosti key2 u uzastopnim iteracijama*/

			bitovi_6>>=10;					/*Siftovanje udesno za 10 mesta. Ovim se dobija da se bitovi sa pozicija
											/*10-15 sada nalaze na pozicijama 0-5. Oni ce se koristiti kao druga 
											/*dimenzija prilikom koriscenja 3D niza ima_jos_key2, kao i tabele 
											/*broj_povezanih_key2*/
				
			for(k=0; k<broj_povezanih_key2[key3list[n-1]][bitovi_6]; k++)
			{
				/*Ako postoji neki key2[n-1] iz kog moze da se dobije prvi_key2 (key2[n])
				/*onda je ta vrednost prvi_key2 "perspektivna", tj. moze da se dobije iz nekog key2[n-1]
				/*i ona se ubacuje u listu mogucih vrednosti key2n.*/

				/*Istovremeno se vrsi i podesavanje bitova na pozicijama 0 i 1. Oni se dobijaju iz mogucih 
				/*vrednosti key2[n-1]*/
				bitovi_2 = ((key2tab[key3list[n-1]][ima_jos_key2[key3list[n-1]][bitovi_6][k]] ^ 
																			invcrc32tab[prvi_key2>>24])>>8)&3;

				key2n[broj_key2n] = prvi_key2 | bitovi_2;
				
				broj_key2n++;	/*Povecava se broj elemenata u listi key2n*/
			}

		}
	}
	printf("Pronadjeno %d kandidata za key2[n]\n", broj_key2n);
}

void redukcija_key2n(unsigned int i)
{
	/*Funkcija koja redukuje broj potencijalnih listi key2*/

	/*Za svaku mogucu vrednost key2n[i] i na osnovu key3[i-1] i key3[i-2], izracunava key2[i-1]. Formira se niz 
	/*key2n_1[i]. Zatim se vrsi sortiranje tog niza, a njegovi elementi se prepisuju u niz key2n, pri cemu se vise 
	/*elemenata sa istom vrednoscu (koji mogu da se dobiju od razlicitih key2n[i]) prepisuju samo jednom (odbacuju 
	/*se duplikati)*/

	unsigned int j, k, s;			/*brojaci u petljama*/
	unsigned int key2_i;			/*key2[i], koji ce uzimati sve moguce elemente niza key2n*/
	unsigned int key2_i_minus_1;	/*key2[i-1], koji treba da se formira*/
	unsigned int key2_i_minus_2;	/*key2[i-2]. Izracunava se samo jedan njegov deo potreban za odredjivanje 
									/*bitova 0 i 1 vrednosti key2[i-1]*/
	unsigned int pomocni_key2;		/*vrednost koja ce se koristiti pri izracunavanju key2[i-1]*/

	broj_key2n_1 = 0;			/*Postavlja se na nulu broj elemenata niza key2n_1 koji treba da se dobije*/

	for(j=0; j<broj_key2n; j++)
	{

		key2_i = key2n[j];		/*Uzima se jedan po jedan element niza key2n i na osnovu njega i poznatih key3[i-1]
								/*i key3[i-2] izracunava se key2[i-2] i upisuje se u niz key2n_1*/

		/*Vrednost key2[i-1] cemo dobiti iz tri koraka
		/*a) key2[i-1](bitovi 8-31) = (key2[i]<<8) xor invcrc32tab[MSB(key2[i])]
		/*b) key2[i-1](bitovi 2-7) = bitovi 2-7 svih vrednosti key2tab[key3[i-1]][k] koje daju key3[i-1]
		/*c) key2[i-1](bitovi 0-1) = bitovi 8-9 svih vrednosti (key2tab[key3[i-2]][k] xor invcrc32tab[MSB(key2[i-1])])
									 koji daju key3[i-2]*/

		key2_i_minus_1 = (key2_i<<8)^invcrc32tab[key2_i>>0x18]^0x00;	/*key2[i-1]=(key2[i]<<8) xor 
																			  invcrc32tab[MSB(key2[i])]*/
		key2_i_minus_1 = key2_i_minus_1 & 0xffffff00;	/*podesava se da bitovi 0-7 budu jednaki nula*/
	
		for(k=0; k<broj_povezanih_key2[key3list[i-1]][(key2_i_minus_1 & 0xfc00)>>10]; k++)
		{
			/*U ovoj petlji se pronalaze sve moguce kombinacije za bitove 2-7 vrednosti key2[i-1].
			/*U svakoj iteraciji se uzima jedna po jedna vrednost iz key2tab[key3list[i-1]] koja ima iste bitove 10-15
			/*kao key2[i-1] (bitovi 8-31 ove vrednosti su dobijene u prethodnom koraku)*/
	
			if((key2tab[key3list[i-1]] [ima_jos_key2[key3list[i-1]][(key2_i_minus_1 & 0xfc00)>>10][k]] & 0xff00) 
																					== (key2_i_minus_1 & 0xff00))
			{
				/*Dodaju se svi moguci "povoljni" bitovi 2-7, na vec dobijene bitove 8-31*/
				pomocni_key2=key2_i_minus_1 | 
								key2tab[key3list[i-1]] [ima_jos_key2[key3list[i-1]][(key2_i_minus_1 & 0xfc00)>>10][k]];

				/*Bitovi 2-31 vrednosti key2[i-1] su sada poznati, pa se mogu izracunati bitovi 10-31 vrednosti 
				/*key2[i-2] koristeci formulu key2[i-2] = (key2[i-1]<<8) xor invcrc32tab[MSB(key2[i-1])] xor MSB(key1[i-i])
				/*Kako MSB(key1[i-1]) utice samo na najnizih 8 bitova, moze se umesto njega uzeti 0x00*/
				key2_i_minus_2 = (pomocni_key2<<8) ^ invcrc32tab[pomocni_key2>>0x18] ^ 0x00;
				key2_i_minus_2 = (key2_i_minus_2 & 0xfc00) >> 10;	/*Podesava se da bitovi 10-15 predju na mesta 0-5
																	/*da bi mogli da se koriste kao indeks u ima_jos_key2*/

				for(s=0; s<broj_povezanih_key2[key3list[i-2]][key2_i_minus_2]; s++)
				{
					/*Podesavaju se sve "povoljne" vrednosti za bitove 0-1 vrednosti key2[i-1]*/
					pomocni_key2 = key2_i_minus_1 |
						(((key2tab[key3list[i-2]] [ima_jos_key2[key3list[i-2]][key2_i_minus_2][s]] ^ 
																	invcrc32tab[key2_i_minus_1>>0x18])>>8)&0xff);
					/*Ovaj gornji izraz je dobijen iz:
					/*key2[i-2] = (key2[i-1]<<8) xor invcrc32tab[MSB(key2[i-1])] xor MSB(key1[i-1]), koji se 
					/*transformise u (key2[i-1]<<8) = key2[i-2] xor invcrc32tab[MSB(key2[i-1])] xor MSB(key1[i-1]).
					/*Vrseno je siftovanje za 8 udesno jer su nam potrebni samo bitovi sa pozicija 8-9 (koji siftovanjem
					/*prelaze na pozicije 0-1), pa samim tim xor MSB(key1[i-1]) nije potrebno racunati. Na kraju se
					/*kompletno izracunavanje svodi na key2[i-1] = (key2[i-2] xor invcrc32tab[MSB(key2[i-1])]) >> 8 */

					/*Dobijena je kompletna vrednost key2[i-1], koja se postavlja u listu mogucih vrednosti key2n_1*/
					key2n_1[broj_key2n_1] = pomocni_key2;

					broj_key2n_1++;		/*povecava se broj dobijenih elemenata niza key2n_1*/
				}
			}
		}
	}

	/*Dobijen je niz mogucih vrednosti key2[i-1], medju kojima ima nekih istih elemenata*/

	sortiranje(0, broj_key2n_1); /*Sortira se dobijeni niz key2n_1*/

	/*Elementi niza key2n_1 se prepisuju u niz key2n, pri cemu se svi elementi niza key2n_1 koji imaju iste vrednosti
	/*prepisuju samo jednom (odbacuju se duplikati)*/

	broj_key2n = 0;		/*Broj prepisanih elemenata se postavlja na nulu*/

	key2n[0]=key2n_1[0];	/*Prepisuje se prvi element*/
	broj_key2n++;

	for(j=1; j<broj_key2n_1; j++)
	{
		if(key2n_1[j] != key2n_1[j-1])
		{				/*Ako je sledeci element niza key2n_1 razlicit od prethodnog, prepisuje se u niz key2n,
						/*a u suprotnom se ide na ispitivanje sledeceg elementa niza key2n_1*/	
			key2n[broj_key2n]=key2n_1[j];
			broj_key2n++;
		}
	}
}

void sortiranje(int i, int j)
{	
	/*Funkcija koja sortira (Quicksort algoritmom) niz key2n_1. Nece biti mnogo komentara jer je ovo implementacija 
	klasicnog Quicksort algoritma*/
	int	k, l;
	unsigned int srednji, pomocni;

    while(i < j-1) 
	{
		srednji = key2n_1[(i+j)/2];
		for(k=i, l=j, key2n_1[(i+j)/2]=key2n_1[i]; k < l; )
		{
			while((k < l) && (key2n_1[l] > srednji)) 
				l--;
			key2n_1[k] = key2n_1[l];
			while((k < l) && (key2n_1[k] <= srednji)) 
				k++;
			key2n_1[l] = key2n_1[k];
		}
		key2n_1[k] = srednji;

		if((k-1-i) < (j-k-1)) 
		{
			sortiranje( i, k-1 );
			i = k+1;
		} 
		else 
		{
			sortiranje(k+1, j);
			j = k-1;
		}
	}

	if((i == j-1) && (key2n_1[i] > key2n_1[j])) 
	{
		pomocni = key2n_1[i];
		key2n_1[i] = key2n_1[j];
		key2n_1[j] = pomocni;
	}
}

void formiraj_listu_key2(unsigned int key2_13)
{
	/*Funkcija dobija, kao argument, poslednji element u nizu key2[2]-key2[13] i iz njega rekonstruise ceo
	/*potencijalni niz key2[i]*/
	key2list[12]=key2_13;
	key2_rekurzija(12);	/*Poziv funkcije u kojoj se u svakom koraku rekurzije formira jedan po jedan element key2[i]*/
}

void key2_rekurzija(int i)
{
	/*Funkcija koja na osnovu key2[i], key3[i-1] i key3[i-2], izracunava key2[i-1], a takodje se dobija i MSB(key1[i])*/

	unsigned int k,s;				/*brojaci u petljama*/
	unsigned int key2_i_minus_1;	/*key2[i-1], koji treba da se formira*/
	unsigned int key2_i_minus_2;	/*key2[i-2]. Izracunava se samo jedan njegov deo potreban za odredjivanje 
									/*bitova 0 i 1 vrednosti key2[i-1]*/
	unsigned int novi_key2;			/*novi kandidat za key2[i-1]*/
	unsigned int stara_vrednost_key2;	/*vrednost key2[i-1] koja je dobijena u prethodnom izracunavanju*/

	/*Vrednost key2[i-1] se dobija iz tri koraka (na isti nacin kao kod vrsenja redukcije broja listi key2)
	/*a) key2[i-1](bitovi 8-31) = (key2[i]<<8) xor invcrc32tab[MSB(key2[i])]
	/*b) key2[i-1](bitovi 2-7) = bitovi 2-7 svih vrednosti key2tab[key3[i-1]][k] koje daju key3[i-1]
	/*c) key2[i-1](bitovi 0-1) = bitovi 8-9 svih vrednosti (key2tab[key3[i-2]][k] xor invcrc32tab[MSB(key2[i-1])])
								 koji daju key3[i-2]*/

	if(i==1)
	{
		broj_listi_key2n++;		/*Povecava se broj pronadjenih kompletnih listi key2[2]-key2[13]*/
		formiraj_listu_key1();	/*Ako je kompletirana lista vrednosti key2[i] (key2[2]-key2[13]), prelazi se na*/
		return;					/*izracunavanje moguce liste vrednosti key1[i] i izlazi se iz rekurzije*/

	}

	stara_vrednost_key2 = 0;		/*Jos uvek nije dobijen ni jedan kandidat za key2[i-1]*/

	key2_i_minus_1 = (key2list[i]<<8)^invcrc32tab[key2list[i]>>0x18]^0x00;	/*key2[i-1]=(key2[i]<<8) xor 
																			  invcrc32tab[MSB(key2[i])]*/
	key2_i_minus_1 = key2_i_minus_1 & 0xffffff00;	/*Podesava se da bitovi 0-7 budu jednaki nula*/
	
	for(k=0; k<broj_povezanih_key2[key3list[i-1]][(key2_i_minus_1 & 0xfc00)>>10]; k++)
	{
		/*U ovoj petlji se pronalaze sve moguce kombinacije za bitove 2-7 vrednosti key2[i-1].
		/*U svakoj iteraciji se uzima jedna po jedna vrednost iz key2tab[i-1] koja ima iste bitove 10-15
		/*kao key2[i-1] (bitovi 8-31 ove vrednosti su dobijeni u prethodnom koraku)*/

		if((key2tab[key3list[i-1]] [ima_jos_key2[key3list[i-1]][(key2_i_minus_1 & 0xfc00)>>10][k]] & 0xff00) 
																					== (key2_i_minus_1 & 0xff00))
		{
			/*Dodaju se svi moguci "povoljni" bitovi 2-7, na vec dobijene bitove 8-31*/
			novi_key2=key2_i_minus_1 | 
							key2tab[key3list[i-1]] [ima_jos_key2[key3list[i-1]][(key2_i_minus_1 & 0xfc00)>>10][k]];

			/*Sad su poznati bitovi 2-31 vrednosti key2[i-1], pa se mogu izracunati bitovi 10-31 vrednosti key2[i-2]
			/*koristeci formulu key2[i-2] = (key2[i-1]<<8) xor invcrc32tab[MSB(key2[i-1])] xor MSB(key1[i-i])
			/*Kako MSB(key1[i-1]) utice samo na najnizih 8 bitova, moze se umesto njega uzeti 0x00*/
			key2_i_minus_2 = (novi_key2<<8) ^ invcrc32tab[novi_key2>>0x18] ^ 0x00;
			key2_i_minus_2 = (key2_i_minus_2 & 0xfc00) >> 10;	/*Podesava se da bitovi 10-15 predju na mesta 0-5
																/*da bi mogli da se koriste kao indeks u ima_jos_key2*/

			for(s=0; s<broj_povezanih_key2[key3list[i-2]][key2_i_minus_2]; s++)
			{
				/*Podesavaju se sve "povoljne" vrednosti za bitove 0-1 vrednosti key2[i-1]*/
				novi_key2 = key2_i_minus_1 |
					(((key2tab[key3list[i-2]] [ima_jos_key2[key3list[i-2]][key2_i_minus_2][s]] ^ 
																invcrc32tab[key2_i_minus_1>>0x18])>>8)&0xff);
					/*Ovaj gornji izraz je dobijen iz:
					/*key2[i-2] = (key2[i-1]<<8) xor invcrc32tab[MSB(key2[i-1])] xor MSB(key1[i-1]), koji se transformise
					/*u (key2[i-1]<<8) = key2[i-2] xor invcrc32tab[MSB(key2[i-1])] xor MSB(key1[i-1]).
					/*Vrseno je siftovanje za 8 udesno jer su nam potrebni samo bitovi sa pozicija 8-9 (koji siftovanjem
					/*prelaze na pozicije 0-1), pa samim tim xor MSB(key1[i-1]) nije potrebno racunati. Na kraju se
					/*kompletno izracunavanje svodi na key2[i-1] = (key2[i-2] xor invcrc32tab[MSB(key2[i-1])]) >> 8 */

				if(novi_key2 != stara_vrednost_key2)
				{
					/*Ako je novi kandidat za key2[i-1] razlicit od vrednosti key2[i-1] dobijene u prethodnoj iteraciji
					/*postavlja se nova vrednost key2[i-1]*/
					key2list[i-1] = novi_key2;

					/*Iz poznatih key2[i] i key2[i-1], izracunava se MSB(key1[i]):
					/*MSB(key1[i]) = (key2[i]<<8) xor invcrc32tab[MSB(key2[i])] xor key2[i-1]*/
					key1list[i] = (key2list[i]<<8) ^ invcrc32tab[(key2list[i]>>0x18)&0xff] ^ key2list[i-1];
					key1list[i] = (key1list[i] & 0xff) << 0x18;
	
					/*Poziva se funkcija za nalazenje sledece vrednosti (key2[i-2]) u listi vrednosti key2*/
					key2_rekurzija(i-1);

					/*Postavlja se novodobijena vrednost za key2[i] za staru vrednost*/
					stara_vrednost_key2 = novi_key2;

					/*Ispituje se da li su pronadjene liste vrednosti kompletne key0-key3 koje se koriste prilikom sifrovanja.
					/*Ako to jeste slucaj, obustavlja se dalje trazenje*/
					if(nadjena_kompletna_lista==1)
						return;
				}
			}
		}
	}
}

void formiraj_listu_key1(void) 
{
	int j;						/*brojac u petljama*/
	unsigned int	key1n_1;	/*vrednost koja predstavlja key1list[n-1]+LSB(key0list[n])*/

	/*U funkciji key2_rekurzija su formirani bajtovi najvece tezine vrednosti key1[2]-key1[n].
	/*U petlji se uzimaju sve moguce vrednosti za nepoznatih 24 bita (na pozicijama 0-23) vrednosti key1list[n].*/
	/*Nece svi brojevi dati listu vrednosti key1, vec ce se dobiti samo 2^16 listi (umesto 2^24)*/

	for(j=0; j<0x1000000; j++)
	{
		/*Postavlja se sledeca moguca vrednost bitova 0-23 vrednosti key1list[12]*/
		key1list[12] = (key1list[12] & 0xff000000) + j;

		key1n_1=(key1list[12]-1)*3645876429;	/*Dobijena je vrednost key1list[n-1]+LSB(key0list[n]).*/
												/*3645876429 predstavlja 134775813^(-1)*/

		/*Ako se podudaraju vrednosti bajta najvece tezine kod key1n_1 i key1list[n-1] ili se poklapaju
		/*bajtovi najvece tezine key1n_1-255 i key1list[n-1], nastavlja se dalje i trazi se kompletna vrednost
		/*za key1list[n-1], inace se prelazi na sledecu mogucu listu za key1
		/*Bajtovi najvece tezine se razlikuju najvise za 1, zato se ispituju samo dve varijante, a ne vise*/

		if(((key1n_1&0xff000000)!=(key1list[11]&0xff000000)) || (((key1n_1-255)&0xff000000)!=(key1list[11]&0xff000000)))
			continue;				/*Nije pronadjeno poklapanje. Zavrsava se tekuca iteracija petlje i prelazi se 
									/*na ispitivanje sledece mogucnosti*/
		
		/*U suprotnom se ulazi u rekurziju koja ce formirati kompletnu potencijalnu listu vrednosti key1[4]-key1[n]*/
		/*Kao argument prosledjuje se redni broj elementa liste key1 koji treba dobiti*/
		key1_rekurzija(12);

		/*Ako je pronadjena odgovarajuca kompletna lista vrednostikey0, key1 i key2, zaustavlja se dalje trazenje*/
		if(nadjena_kompletna_lista==1)
			return;
	}
}

void key1_rekurzija(unsigned int i)
{
	/*Funkcija koja na osnovu poznate kompletne vrednosti key1[i] i poznatih MSB(key1[i-1]) i MSB(key1[i-2])
	/*izracunava kompletnu vrednost key1[i-1], formira LSB(key0[i]) i ako je dobijena kompletna lista key1,
	/*poziva funkciju za dobijanje liste key0*/

	int k;							/*brojac u petljama*/
	unsigned int key1_i_minus_1;	/*key1[i-1]*/
	unsigned int key1_i_minus_2;	/*key1[i-2]*/


	/*Ako je formirana kompletna lista vrednosti key1[4]-key1[12], prelazi se na formiranje liste key0*/
	if(i==3)
		{
			formiraj_listu_key0();
			return;
		}

	/*Koristi se formula key1[i-1] + LSB(key0[i]) = (key1[i] - 1) * 3645876429 
	
	/*Posto je poznat kopmpletan key1[i], moze se dobiti kompletna vrednost (key1[i] - 1) * 3645876429.
	/*key1[i-1] i key1[i-1]+LSB(key0[i]) se mogu razlikovati jedino za neku vrednost iz intervala 0-255.
	/*Posto je to bajt najmanje tezine, kada se to prenese do bajta najvece tezine, oni se mogu razlikovati 
	/*najvise za 1. Zato ce se uvek proveravati podudaranje bajtova najvece tezine vrednosti dobijene pomocu
	/*(key1[i] - 1) * 3645876429 sa bajtom najvece tezine vrednosti key1[i-1] i key1[i-1]+255*/

	key1_i_minus_1=(key1list[i]-1)*3645876429;	/*Dobili smo vrednost key1list[i-1]+LSB(key0list[i])*/

	/*Ako se ne poklapaju odgovarajuci bajtovi najvece tezine, izlazi se iz rekurzije i pokusava se sa sledecim key1[12]*/
	if(((key1_i_minus_1 & 0xff000000) != (key1list[i-1] & 0xff000000)) ||
				(((key1_i_minus_1 - 255) & 0xff000000) != (key1list[i-1] & 0xff000000)))
		return;

	/*Ako se bajtovi najvece tezine poklapaju, prelazi se na izracunavanje konkretne, kompletne, vrednosti key1[i-1]*/
	
	/*key1[i-1] se nalazi u intervalu [key1_i_minus_1 - key1_i_minus_1-255].
	/*Zato se uzimaju sve moguce vrednosti iz tog intervala i utvrdjuje se koja od njih daje odgovarajucu
	/*vrednost MSB(key1[i-2]), koja je vec poznata.
	/*Koristice se formula: key1[i-2] + LSB(key0[i-1]) = (key1[i-1] - 1) * 3645876429.
	/*Za svaku od 256 mogucnosti key1[i-1], izracunava se (key1[i-1] - 1) * 3645876429, a zatim se uporedjuje 
	/*dobijeni bajt najvece tezine sa MSB(key1[i-2]) i MSB(key1[i-2]+255). 
	/*Kad se dobije poklapanje, znaci da je dobijen kompletan key1[i-1]*/
	
	for(k=0; k<256; k++)
	{
		key1_i_minus_2 = ((key1_i_minus_1 - k) - 1) * 3645876429;	/*Za sve moguce key1[i-1] iz intervala 
																	/*key1_i_minus_1 - (key1_i_minus_1-255),
																	/*izracunava se vrednost key1[i-2]*/
		if((key1_i_minus_2 & 0xff000000) == (key1list[i-2] & 0xff000000) ||
				((key1_i_minus_2 - 255) & 0xff000000) == (key1list[i-2] & 0xff000000))
		{	
			key1list[i-1] = key1_i_minus_1 - k;	/*Ako je pronadjeno poklapanje, dobijena je vrednost key1[i-1]*/

			/*Posto je LSB(key0[i]) = (key1[i] - 1) * 3645876429 -  key1[i-1], tj u nasem slucaju
			/*LSB(key0[i]) = key1_i_minus_1 - key1[i-1], to znaci da je LSB(key0[i]) = k.*/
			key0list[i] = k;
			key0list[i] = key0list[i] & 0xff;

			/*Prelazi se na izracunavanje vrednosti key1[i-2]*/
			key1_rekurzija(i-1);
//			break;			/*Logicno je da ovde treba ubaciti komandu break; ali testiranjem je dobijeno da
							/*moze doci do vise poklapanja bajtova najvece tezine key1[i-2] i key1_i_minus_2*/
		}
	}

	/*Ispituje se da li su pronadjene liste vrednosti kompletne key0-key3 koje se koriste prilikom sifrovanja.
	/*Ako to jeste slucaj, obustavlja se dalje trazenje*/
	if(nadjena_kompletna_lista==1)
		return;
}

void formiraj_listu_key0()
{
	/*Funkcija koja na osnovu poznatih LSB(key0list[i]), formira kompletnu listu key0list[i]; zatim proverava da
	/*li je to odgovarajuca lista, koja se zaista formira pri sifrovanju arhive, i ako je to tacno, onda kompletira
	/*listu svih vrednosti key0list[i], key1list[i] i key2list[i], stampa odgovarajucu poruku i zaustavlja dalji
	/*rad programa*/

	unsigned int pom;	/*pomocna promenljiva*/
	int i;				/*brojac u petlji*/
	unsigned char nesifr_bajt;	/*nesifrovani bajt koji ce odgovarati jednom po jednom sifrovanom prepended bajtu*/

	/*Sve sto treba dobijace se pomocu formule*/
	/*key0list[i+1] = (key0list[i]>>8) xor crc32tab[LSB(key0list[i]) xor nesifr_podaci[i]].*/
	/*Ona se transformise u:
	/*key0list[i]>>8 = key0list[i+1] xor crc32tab[LSB(key0list[i]) xor nesifr_podaci[i]].

	/*Za key0list[12] i key0list[11] su poznati bitovi 0-7, za crc32tab[((key0list[11]&0xff)^nesifr_podaci[11])&0xff]
	/*su poznati bitovi 0-31, pa se dobijaju bitovi 0-7 za promenljivu pom. Ako se siftuju za 8 mesta ulevo, dobijaju se
	/*bitovi 8-15 vrednosti key0list[11]. Kako su vec poznati bitovi na pozicijema 0-7, sada su poznati bitovi 0-15
	/*vrednosti key0list[11]*/
	pom=key0list[12] ^ crc32tab[((key0list[11]&0xff)^nesifr_podaci[11])&0xff];
	key0list[11]=key0list[11] | ((pom&0xff)<<8);

	/*Analognim postupkom dobijaju se bitovi 0-23 vrednosti key0list[10]*/
	pom=key0list[11] ^ crc32tab[((key0list[10]&0xff)^nesifr_podaci[10])&0xff];	/*Dobijeni su bitovi 0-15.*/
	key0list[10]=key0list[10] | ((pom&0xffff)<<8);		/*Dobijeni su bitovi 8.-23. vrednosti key0list[10], a kako
														/*su od ranije poznati bitovi 0-7, sada su poznati bitovi 0-23.*/
	
	/*U sledecem koraku se dobija kompletna vrednost key0list[9]*/
	pom=key0list[10] ^ crc32tab[((key0list[9]&0xff)^nesifr_podaci[9])&0xff];	/*Dobijeni su bitovi 0-23.*/
	key0list[9]=key0list[9] | ((pom&0xffffff)<<8);		/*Dobijeni su bitovi 8-31 vrednosti key0list[9], a kako su
														/*od ranije bili poznati bitovi 0-7, sada je poznata kompletna
														/*vrednost key0list[9]*/

	/*Kada je poznata jedna kompletna vrednost key0list[i], moze se ici unapred i dobijati naredne vrednosti key0list[j],
	/*j>i, koristeci formulu key0list[i+1] = (key0list[i]>>8) xor crc32tab[LSB(key0list[i]) xor nesifr_podaci[i]]
	/*ili ici unazad i dobijati prethodne vrednosti key0list[j], j<i, koristeci formulu 
	/*key0list[i-1] = (key0list[i]<<8) xor invcrc32tab[MSB(key0list[i])] xor nesifr_podaci[i-1]. 
	/*Ove formule se mogu primenjivati samo dok su poznati podaci iz nesifrovane ulazne arhive*/

	/*Sad kada je pronadjen kompletan key0list[9], popunjavaju se ostali podaci u key0list[10], key0list[11]
	/*i key0list[12].*/
	key0list[10] = (key0list[9]>>8) ^ crc32tab[((key0list[9]&0xff) ^ nesifr_podaci[9])&0xff];
	key0list[11] = (key0list[10]>>8) ^ crc32tab[((key0list[10]&0xff) ^ nesifr_podaci[10])&0xff];
	key0list[12] = (key0list[11]>>8) ^ crc32tab[((key0list[11]&0xff) ^ nesifr_podaci[11])&0xff];

	/*Posto su poznate kompletne key0list[9]-key0list[12], koristeci formulu 
	/*key0list[i]=(key0list[i+1]<<8) xor invcrc32tab[MSB(key0list[i+1])] xor nesifr_podaci[i], i znajuci 
	/*nesifr_podaci[0]-nesifr_podaci[12] dobijaju se i kompletne ostale vrednosti key0list[4]-key0list[8],
	/*ciji ce se bajtovi najmanje tezine uporedjivati sa bajtovima najmanje tezine vec dobijenih vrednosti za key0list.
	/*Ako dodje do poklapanja svih 5 bajtova, pronadjena je lista vrednosti za key0 koja se koristi u sifrovanju fajla*/
	for(i=0; i<5; i++)
	{
		pom=((key0list[9-i]<<8) ^ invcrc32tab[key0list[9-i]>>0x18]) ^ (nesifr_podaci[8-i]&0xff);
		if((pom & 0xff) != (key0list[8-i] & 0xff))
			return;		/*Ako se bajtovi najmanje tezine ne poklapaju prekida se petlja i prelazi se na
						/*ispitivanje sledece moguce liste vrednosti za key0list*/

		/*Ako se bajtovi najmanje tezine poklapaju, postavlja se vrednost za key0list[8-i]*/
		key0list[8-i]=pom;
	}

	/*Pronadjena je odgovarajuca kombinacija lista vrednosti koja je bila koriscena u procesu sifrovanja arhive*/
	printf("PRONADJEN INTERNI KLJUC:\n");

	/*Sada, kada su poznati kompletni key0list[i], key1list[i] i key2list[i], 4<i<12, prelazi se na kompletiranje
	/*svih listi vrednosti za 0<i<3*/
	for(i=4; i>0; i--)
	{
		/*key2[i-1] = (key2[i]<<8) xor invcrc32tab[MSB(key2[i])] xor MSB(key1[i])*/
		key2list[i-1] = ((key2list[i]<<8) ^ invcrc32tab[key2list[i]>>0x18]) ^ ((key1list[i]>>0x18)&0xff);

		/*key1[i-1]=((key1[i]-1)*3645876429)-LSB(key0[i])*/
		key1list[i-1] = ((key1list[i] - 1) * 3645876429) - (key0list[i] & 0xff);

		/*pom = key2[i-1] or 3*/
		pom = key2list[i-1] | 3;

		/*key3[i-1]=LSB((pom * (pom xor 1))>>8)*/
		key3list[i-1] = ((pom * (pom ^ 1))>>8) & 0xff;

		/*key0[i-1]=(key0[i]<<8) xor invcrc32tab[MSB(key0[i])] xor nesifr_podaci[i-1]*/
		key0list[i-1] = ((key0list[i]<<8) ^ invcrc32tab[key0list[i]>>0x18]) ^ (nesifr_podaci[i-1]&0xff);
	}

	/*Posto je na pocetak sifrovane arhive dodato 11 random bajtova i 12. bajt koji predstavlja MSB(crc32 value)
	/*datog fajla, mora se videti njihov sifrovan oblik (dobijen kao argument funkcije) i ici unazad (do pocetka fajla) 
	/*desifrujuci ih. Njihove nesifrovane vrednosti nisu bitne za samo nalazenje sifre, tako da se nece nigde 
	/*pamtiti, niti ispisivati. Bitne su samo vrednosti internog kljuca (key0, key1 i key2) pre kombinovanja sa 
	/*tih 12 bajtova, jer je to vrednost dobijena posle kombinovanja sa lozinkom*/

	/*Posto treba ici 12 koraka unazad postavlja se da trenutno pronadjeni interni kljuc postane 12. element u 
	/*listama key0list, key1list i key2list*/
	key0list[0xc]=key0list[0];
	key1list[0xc]=key1list[0];
	key2list[0xc]=key2list[0];

	/*Posto su poznati 12 bajtova i vrednosti internog kljuca na kraju (posle kombinovanja sa tih 12 bajtova),
	/*rekonstruise se vrednost internog kljuca pre kombinovanja sa tih 12 bajtova*/
	for(i=0xc; i>0; i--)
	{
		/*key2[i-1] = (key2[i]<<8) xor invcrc32tab[MSB(key2[i])] xor MSB(key1[i])*/
		key2list[i-1] = ((key2list[i]<<8) ^ invcrc32tab[key2list[i]>>0x18]) ^ ((key1list[i]>>0x18)&0xff);

		/*key1[i-1]=((key1[i]-1)*3645876429)-LSB(key0[i])*/
		key1list[i-1] = ((key1list[i] - 1) * 3645876429) - (key0list[i] & 0xff);

		/*pom = key2[i-1] or 3*/
		pom = key2list[i-1] | 3;

		/*key3[i-1]=LSB((pom * (pom xor 1))>>8)*/
		key3list[i-1] = ((pom * (pom ^ 1))>>8) & 0xff;

		/*nesifr_bajt = sifrovani_random_bajt[i-1] xor key3[i-1]*/
		nesifr_bajt = random_bajtovi[i-1] ^ key3list[i-1];

		/*key0[i-1]=(key0[i]<<8) xor invcrc32tab[MSB(key0[i])] xor random_bajtovi[i-1]*/
		key0list[i-1] = ((key0list[i]<<8) ^ invcrc32tab[key0list[i]>>0x18]) ^ (nesifr_bajt&0xff);
	}

	/*Pronadjene su vrednosti internog kljuca (nalaze se u key0list[0], key1list[0] i key2list[0]), koje se 
	/*dobijaju posle kombinacije inicijalnih vrednosti internog kljuca sa dobijenom lozinkom*/

	/*Stampaju se vrednost pronadjenog internog kljuca*/
	printf("key0: 0x%x\n", key0list[0]);
	printf("key1: 0x%x\n", key1list[0]);
	printf("key2: 0x%x\n", key2list[0]);

	/*Ako je program prosao kroz celu petlju, to znaci da je nasao poklapanja svih potrebnih vrednosti za listu key0
	/*sto bi znacilo da je pronasao listu vrednosti koja se koristi za sifrovanje i program treba da prestane 
	/*sa daljim trazenjem*/
	nadjena_kompletna_lista=1;

}

void pronadji_lozinku()
{
	/*Funkcija koja na osnovu poznate vrednosti internog kljuca pronalazi lozinku kojom je sifrovana data arhiva*/

	/*Na redu je pronalazenje konkretne lozinke. Razlikuju se nekoliko slucajeva: 
	/*a) lozinka dugacka 0-4 karaktera,
	/*b) lozinka dugacka 5 ili 6 karaktera,
	/*c) lozinka dugacka vise od 6 karaktera*/

	unsigned int i,j,k;			/*brojaci u petljama*/
	unsigned int pom, pom1, pom2;/*pomocne promenljive*/
	unsigned int key0_i_minus1;	/*vrednost promenljive key0list[i-1]*/
	unsigned int key0_i_minus2;	/*vrednost promenljive key0list[i-2]*/
	unsigned int key0_i_minus3;	/*vrednost promenljive key0list[i-3]*/
	unsigned int key0_i_minus4;	/*vrednost promenljive key0list[i-4]*/
	unsigned int key1_i_minus1;	/*vrednost promenljive key1list[i-1]*/
	unsigned int key2_i_minus1;	/*vrednost promenljive key2list[i-1]*/
	unsigned int key2_i_minus2;	/*vrednost promenljive key2list[i-2]*/
	unsigned int key0, key1, key2;	/*promenljive koje ce se koristiti za proveravanje validnosti dobijene lozinke*/

	pronadjena_lozinka=0;		/*Postavlja se da nije pronadjena lozinka*/

	/*Ako je lozinka duzine nula, odmah se stampa poruka*/
	if(key0list[0]==0x12345678 && key1list[0]==0x23456789 && key2list[0]==0x34567890)
	{
		printf("Pronadjena je lozinka duzine 0, tj. nije uneta nikakva lozinka\n");
		return;
	}
	else
	{
		printf("Lozinka nije duzine 0. Ispitujemo lozinke duzine 1...\n");

		/*Ako je lozinka dugacka 1, 2, 3 ili 4 karaktera, lozinka se dobija iz formule:*/
		/*key0[i+1] = crc(key0[i], char), koja se koristi pri azuriranju vrednosti key0, key1 i key2 u 
		/*zavisnosti od unetog karaktera.*/

		/*key0[i] = (key0[i+1]<<8) xor invcrc32tab[MSB(key0[i+1])] xor char*/
		/*Ako je poznata vrednost key0list[0], u prvom koraku se dobijaju gornja 3 bajta vrednosti key0[-1]. 
		/*Ako se oni poklapaju sa gornja tri bajta vrednosti 0x12345678, dobijena je lozinka cija je duzina 1.*/
		/*Analognim postupkom, u sledecem koraku se dobijaju poznata gornja 2 bajta vrednosti key0[-2], 
		/*uporedjuju se sa gornja dva bajta vrednosti 0x12345678, i ako se poklapaju, dobijena je lozinka duzine 2*/
		/*Slicno se dobija lozinka duzine 3*/

		/*Posto su bitna samo gornja 3 bajta, moze se staviti char=0x00, jer to ne utice na njih*/
		key0_i_minus1 = ((key0list[0]<<8) ^ invcrc32tab[key0list[0]>>0x18]) ^ 0x00;
		if((key0_i_minus1 & 0xffffff00) == (0x12345678 & 0xffffff00))
		{
			/*Nadjena lozinka, duzine 1*/
			/*char = LSB(key0[-1] xor 0x12345678)*/
			lozinka[0] = (key0_i_minus1 ^ 0x12345678) & 0xff;
			/*Ostaje da se proveri da li je to zaista lozinka. Njenim koriscenjem, trebalo bi da se od inicijalnih
			/*vrednosti key0, key1 i key2, dobije pocetna vrednost internog kljuca*/
			key0 = 0x12345678;
			key1 = 0x23456789;
			key2 = 0x34567890;
			key0 = (key0>>8) ^ crc32tab[((key0 & 0xff) ^ lozinka[0])&0xff];
			key1 = (key1 + (key0 & 0xff)) * 134775813 + 1;
			key2 = (key2>>8) ^ crc32tab[((key2 & 0xff) ^ (key1>>0x18)) & 0xff];
			if(key0 == key0list[0] && key1 == key1list[0] && key2 == key2list[0])
			{
				printf("Koriscena je lozinka: %c\n", lozinka[0]);
				return;
			}
		}

		printf("Lozinka nije duzine 1. Ispitujemo lozinke duzine 2...\n");

		/*Lozinka je vece duzine od 1, pa se ispituje da li je duzine 2?*/
		/*Dobijaju se poznata gornja 2 bajta. Uporedjuju se sa gornja dva bajta vrednosti 0x1245678*/
		key0_i_minus2 = ((key0_i_minus1<<8) ^ invcrc32tab[key0_i_minus1>>0x18]) ^ 0x00;
		if((key0_i_minus2 & 0xffff0000) == (0x12345678 & 0xffff0000))
		{
			/*Nadjena je lozinka duzine 2*/
			lozinka[0] = (key0_i_minus2 ^ 0x12345678) & 0xff;
			lozinka[1] = ((key0_i_minus2 ^ 0x12345678) >> 8) & 0xff;
			key0 = 0x12345678;
			key1 = 0x23456789;
			key2 = 0x34567890;
			for(i=0; i<2; i++)
			{
				key0 = (key0>>8) ^ crc32tab[((key0 & 0xff) ^ lozinka[i])&0xff];
				key1 = (key1 + (key0 & 0xff)) * 134775813 + 1;
				key2 = (key2>>8) ^ crc32tab[((key2 & 0xff) ^ (key1>>0x18)) & 0xff];
			}
			if(key0 == key0list[0] && key1 == key1list[0] && key2 == key2list[0])
			{
				printf("Koriscena je lozinka: %c%c\n", lozinka[0], lozinka[1]);
				return;
			}
		}

		printf("Lozinka nije duzine 2. Ispitujemo lozinke duzine 3...\n");

		/*Lozinka je vece duzine od 2, pa se ispituje da li je duzine 3?*/
		/*Dobija se samo jedan poznat bajt (najvece tezine). Uporedjuje se sa bajtom najvece tezine vrednosti 0x12345678*/		
		key0_i_minus3 = ((key0_i_minus2<<8) ^ invcrc32tab[key0_i_minus2>>0x18]) ^ 0x00;
		if((key0_i_minus3 & 0xff000000) == (0x12345678 & 0xff000000))
		{
			/*Nadjena je lozinka duzine 3*/
			lozinka[0] = (key0_i_minus3 ^ 0x12345678) & 0xff;
			lozinka[1] = ((key0_i_minus3 ^ 0x12345678) >> 8) & 0xff;
			lozinka[2] = ((key0_i_minus3 ^ 0x12345678) >> 0x10) & 0xff;
			key0 = 0x12345678;
			key1 = 0x23456789;
			key2 = 0x34567890;
			for(i=0; i<3; i++)
			{
				key0 = (key0>>8) ^ crc32tab[((key0 & 0xff) ^ lozinka[i])&0xff];
				key1 = (key1 + (key0 & 0xff)) * 134775813 + 1;
				key2 = (key2>>8) ^ crc32tab[((key2 & 0xff) ^ (key1>>0x18)) & 0xff];
			}
			if(key0 == key0list[0] && key1 == key1list[0] && key2 == key2list[0])
			{
				printf("Koriscena je lozinka: %c%c%c\n", lozinka[0], lozinka[1], lozinka[2]);
				return;
			}
		}

		printf("Lozinka nije duzine 3. Ispitujemo lozinke duzine 4...\n");

		/*Lozinka je duzine vece od 3, pa se ispituje da li je duzine 4?*/
		/*Iako ovde nema sa cim da se uporedi, kao u gornja tri slucaja, ipak se radi isti postupak,
		/*dobija se potencijalni kadnidat i onda se proverava da li je to trazena lozinka ili nije*/
		key0_i_minus4 = ((key0_i_minus3<<8) ^ invcrc32tab[key0_i_minus3>>0x18]) ^ 0x00;
		lozinka[0] = (key0_i_minus4 ^ 0x12345678) & 0xff;
		lozinka[1] = ((key0_i_minus4 ^ 0x12345678) >> 8) & 0xff;
		lozinka[2] = ((key0_i_minus4 ^ 0x12345678) >> 0x10) & 0xff;
		lozinka[3] = ((key0_i_minus4 ^ 0x12345678) >> 0x18) & 0xff;
		key0 = 0x12345678;
		key1 = 0x23456789;
		key2 = 0x34567890;
		for(i=0; i<4; i++)
		{
			key0 = (key0>>8) ^ crc32tab[((key0 & 0xff) ^ lozinka[i])&0xff];
			key1 = (key1 + (key0 & 0xff)) * 134775813 + 1;
			key2 = (key2>>8) ^ crc32tab[((key2 & 0xff) ^ (key1>>0x18)) & 0xff];
		}
		if(key0 == key0list[0] && key1 == key1list[0] && key2 == key2list[0])
		{
			printf("Koriscena je lozinka: %c%c%c%c\n", lozinka[0], lozinka[1], lozinka[2], lozinka[3]);
			return;
		}

		printf("Lozinka nije duzine 4. Ispitujemo lozinke duzine 5...\n");

		/*Lozinka je duzine vece od 4, pa se primenjuje drugaciji postupak*/
		/*key2[-1] se moze lako pronaci iz formule:
		/*key2[i-1] = (key2[i]<<8) xor invcrc32tab[MSB(key2[i])] xor MSB(key1[i])*/

		/*Ispituje se da li je lozinka duzine 5?*/
		key2_i_minus1 = ((key2list[0]<<8) ^ invcrc32tab[key2list[0]>>0x18]) ^ ((key1list[0]>>0x18)&0xff);
		key0 = 0x12345678;
		key1 = 0x23456789;
		key2 = 0x34567890;
		key1_sifra[6] = key1list[0];	/*Poslednji element mora biti jednak vrednosti key1 internog kljuca*/

		/*Sada se moze ici 4 koraka unazad i nalazi se key2[-2], key2[-3], key2[-4] i key2[-5] jer su key2[i] i key2[i+1]
		/*povezane linearnom funkcijom crc, isto kao key0[i] i key0[i+1]. Ovakav postupak je vec sproveden pri trazenju
		/*lozinke duzine 4*/
		/*Koristice se jednacina: key2[i-1] = (key2[i]<<8) xor invcrc32tab[MSB(key2[i])] xor MSB(key1[i]). Umesto 
		/*MSB(key1[i]) ce se koristiti 0x00, jer ce se uraditi 4 koraka, uporediti dobijeni key2[i-4], sa inicijalnom 
		/*vrednoscu key2 (0x34567890) i odatle naci potencijalne kandidate za MSB(key1[i])*/
		for(i=0; i<4; i++)
			key2_i_minus1 = ((key2_i_minus1<<8) ^ invcrc32tab[key2_i_minus1>>0x18]) ^ 0x00;

		/*Dobijen je key2[-5]. Sada se vrsi uporedjvanje sa 0x34567890*/
		pom = key2_i_minus1 ^ 0x34567890;

		/*Dobijene su potencijalne vrednosti MSB(key1[-4]), MSB(key1[-3]), MSB(key1[-2]), MSB(key1[-1]). One se stavljaju 
		/*u listu vrednosti key1_sifra*/
		key1_sifra[2] = (pom & 0xff) << 0x18;
		key1_sifra[3] = ((pom >> 8) & 0xff) << 0x18;
		key1_sifra[4] = ((pom >> 0x10) & 0xff) << 0x18;
		key1_sifra[5] = ((pom >> 0x18) & 0xff) << 0x18;

		/*Sad se sprovodi isti postupak kompletiranja vrednosti key1_sifra[i], kao kod formiranja kompletnih vrednosti
		/*key1list[i]. Kod ce biti vrlo slican, a komentari o nacinu izracunavanja kompletne liste vaze i u ovom slucaju*/
		/*Na osnovu poznate kompletne vrednosti key1_sifra[i] i poznatih MSB(key1_sifra[i-1]) i MSB(key1_sifra[i-2])
		/*izracunava kompletnu vrednost key1_sifra[i-1], */ 
		/*Kompletirace se vrednosti key1_sifra[3], key1_sifra[4] i key1_sifra[5] (key1_sifra[6] je vec poznata), 
		/*a takodje ce se dobiti LSB(key0_sifra[4]) i LSB(key0_sifra[5])*/
		/*Takodje ce se proveriti i da li je to prava sifra, ako jeste zavrsava se program, a ako nije, ide se dalje
		/*i trazi se sifra duzine 6*/
		key1_sifra5_rekurzija(6);

		if(pronadjena_lozinka == 1)
			return;			/*Ako je pronadjena lozinka duzine 5, izlazi se iz funkcije...*/

		/*...a u suprotnom, se trazi lozinka duzine 6...*/
		printf("Lozinka nije duzine 5. Ispitujemo lozinke duzine 6...\n");

		/*Moze se naci key2[-1], key1[-1] i key2[-2] iz formula: 
		/*key2[i-1] = (key2[i]<<8) xor invcrc32tab[MSB(key2[i])] xor MSB(key1[i]) i 
		/*key1[i-1] = ((key1[i]-1) * 3645876429) - LSB(key0[i])*/
		key2_i_minus1 = ((key2list[0]<<8) ^ invcrc32tab[key2list[0]>>0x18]) ^ ((key1list[0]>>0x18)&0xff);
		key1_i_minus1 = ((key1list[0]-1) * 3645876429) - (key0list[0] & 0xff);
		key2_i_minus2 = ((key2_i_minus1<<8) ^ invcrc32tab[key2_i_minus1>>0x18]) ^ ((key1_i_minus1>>0x18)&0xff);
		key0 = 0x12345678;
		key1 = 0x23456789;
		key2 = 0x34567890;
		key1_sifra[6] = key1_i_minus1;	/*Poslednji element mora biti jednak vrednosti key1[-1]*/

		/*Dalje se primenjuje slican postupak kao kod lozinke dugacke 5*/
		for(i=0; i<4; i++)
			key2_i_minus2 = ((key2_i_minus2<<8) ^ invcrc32tab[key2_i_minus2>>0x18]) ^ 0x00;

		/*Dobijen je key2[-6]. Sada se vrsi uporedjvanje sa 0x34567890*/
		pom = key2_i_minus2 ^ 0x34567890;

		/*Dobijene su potencijalne vrednosti MSB(key1[-5]), MSB(key1[-4]), MSB(key1[-3]), MSB(key1[-2]). One se stavljaju 
		/*u listu vrednosti key1_sifra*/
		key1_sifra[2] = (pom & 0xff) << 0x18;
		key1_sifra[3] = ((pom >> 8) & 0xff) << 0x18;
		key1_sifra[4] = ((pom >> 0x10) & 0xff) << 0x18;
		key1_sifra[5] = ((pom >> 0x18) & 0xff) << 0x18;
		
		/*Na osnovu poznate kompletne vrednosti key1_sifra[i] i poznatih MSB(key1_sifra[i-1]) i MSB(key1_sifra[i-2])
		/*izracunava se kompletna vrednost key1_sifra[i-1], nalaze se ostali potrebni elementi i proverava da li je 
		/*to prava lozinka. Postupak je analogan postupku pri trazenju lozinke duzine 5.*/ 
		duzina_lozinke = 6;
		key1_sifra6_rekurzija(6);

		if(pronadjena_lozinka == 1)
			return;			/*Ako je pronadjena lozinka duzine 6, izlazi se iz funkcije...*/

		/*...a u suprotnom se prelazi na trazenje lozinki duzih od 6 karaktera*/
		/*Pretpostavljeno je da lozinka nije duza od 13 karaktera, jer skoro sve lozinke duze od 13 karaktera imaju neku
		/*ekvivalentnu lozinku duzine do 13 karaktera iz razloga sto je sam interni kljuc dugacak 12 bajtova, pa nema
		/*mogucnosti za veci broj kombinacija. Zato, se mozda nece pronaci lozinka koja je zaista koriscena pri sifrovanju
		/*date arhive, ali ce se pronaci njoj ekvivalentna lozinka kojom se moze desifrovati data sifrovana arhiva.*/

		/*Prvo se pokusava pronaci lozinka duzine 7, pa duzine 8,... i na kraju duzine 13*/
		for(duzina_lozinke=7; duzina_lozinke<14; duzina_lozinke++)	
		{
			printf("Lozinka nije duzine %d. Ispitujemo lozinke duzine %d...\n", (duzina_lozinke-1), duzina_lozinke);

			/*Poslednjih 6 karaktera se nalaze na isti nacin kao kod trazenja lozinke duzine 6, dok se prvi karakteri 
			/*lozinke (lozinka[0] - lozinka[duzina_lozinke-7]) uzimaju na sve moguce nacine. 
			/*Ukupno ih ima duzina_lozinka-6, svaki moze imati 256 razlicitih vrednosti, a ukupno mogucih 
			/*256^(duzina_lozinke-6) kombinacija, tj. (2^8)^{duzina_lozinke-6}*/

			if(duzina_lozinke>6 && duzina_lozinke<10)
			{	
				pom1 = (1<<(8*(duzina_lozinke-6)))-1;	/*pom1 predstavlja broj mogucih kombinacija vrednosti prvih 
														/*duzina_lozinke-6 bajtova (karaktera) lozinke*/
				pom2 = 0;			/*pom2 uzima vrednost 0, kao pokazatelj da nema vise od 4 karaktera koji se uzimaju 
									/*na proizvoljan nacin*/
			}
			/*pom1 je unsigned int, sto znaci da moze da ima 2^32 mogucih vrednosti, pa se samo njegovom upotrebom mogu
			/*pokriti lozinke duzine 7, 8, 9 ili 10 (ako je lozinka duzine 10, pom1 uzima vrednost 0xffffffff), a za 
			/*vece duzine se mora koristiti i pom2*/
			else
			{
				pom1 = 0xffffffff;						/*Za prva 4 karaktera lozinke postoji 2^32 mogucih kombinacija*/
				pom2 = (1<<(8*(duzina_lozinke-10)))-1;	/*a za preostalih duzina_lozinke-10 bajtova se odredjuje broj svih
														/*mogucih kombinacija*/
			}

			for(i=0; i<=pom1; i++)
			{
				/*Prvih duzina_lozinke-6 karaktera lozinke dobijaju sve moguce vrednosti*/

				/*Odredjuju se prvih duzina_lozinke-6 bajtova (ako je lozinka duzine 7-10) ili prva 4 bajta (ako je 
				/*lozinka duzine vece od 10). Svaki bajt vrednosti pom1 odredjuje vrednost po jednog karaktera lozinke*/
				for(j=0; (j<(duzina_lozinke-6)) && j<4; j++)
					lozinka[j] = ((i >> (8 * j)) & 0xff);	/*lozinka[0] = LSB(i); ...; 
																	lozinka[duzina_lozinke-7] = MSB(i)*/

				/*Ako je  pitanju lozinka duzine vece od 10, onda se proizvoljno mora postaviti jos 
				/*duzina_lozinke-10 bajtova*/
				if(pom2 != 0)
					for(k=0; k<=pom2; k++)
					{
						if(pronadjena_lozinka == 1)
							return;			/*Ako je pronadjena lozinka, izlazi se iz funkcije...*/

						for(j=0; j<(duzina_lozinke-0xa); j++)
							lozinka[j+4] = (k >>(8 * j)) & 0xff;
						pronadji_dugacku_lozinku(duzina_lozinke);
					}
				else
				{
					pronadji_dugacku_lozinku(duzina_lozinke);
					if(pronadjena_lozinka == 1)
						return;			/*Ako je pronadjena lozinka, izlazi se iz funkcije...*/
				}
			}
		}

		/*Ako program u nekom slucaju ipak stigne do ove tacke (mada ne bi trebalo), stampa se poruka da nije uspelo
		/*trazenje lozinke, a to bi znacilo da sam program treba da se modifikuje tako da trazi i lozinke duzine vece 
		/*od 13, a to bi zahtevalo veoma dug rad samog programa, jer bi njegova (ionako velika) slozenost porasla na 
		/*preko 2^56(koliko treba za samo trazenje svih lozinki duzine 13) * 2^38(koliko treba za nalazenje internog
		/*kluca). Znaci slozenost ce preci 2^96, sto sa sadasnjom tehnologijom ne daje garanciju za zavrsetak u nekom 
		/*realnom vremenskom periodu*/
		printf("Program nije uspeo da pronadje odgovarajucu sifru\n");
	}
}

void key1_sifra5_rekurzija(unsigned int i)
{
	/*Funkcija slicna funkciji key1_rekurzija, samo sto se koristi pri nalazenju kompletne liste key1_sifra.
	/*Koristi se za pronalazenje lozinke duzine 5.
	/*Parametar pokazuje koji je element poslednji ceo poznat i pokazuje da se trazi kompletan key0_sifra[i-1]*/

	unsigned int key1_i_minus1;	/*vrednost promenljive key1_sifra[i-1]*/
	unsigned int key1_i_minus2;	/*vrednost promenljive key1_sifra[i-2]*/
	unsigned int key0_i_minus1;	/*vrednost promenljive key0list[-1]*/
	unsigned int key0, key1, key2;	/*promenljive koje ce se koristiti za proveravanje validnosti dobijene lozinke*/

	unsigned int j, k, s;		/*brojaci u petljama*/
	unsigned int pom;			/*pomocna promenljiva*/

	if(pronadjena_lozinka==1)
		return;		/*Ako je pronadjena lozinka, prekida se dalje trazenje*/

	if(i==4)		/*Ako su pronadjeni kompletni key1_sifra[3]-key1_sifra[6], izlazi se iz rekurzije i nastavlja se 
					/*sa daljim ispitivanjem, da li se ova nadjena lista key1_sifra[i] zaista formira pri sifrovanju*/
	{
		/*Trazi se poslednji, peti karakter, u lozinki duzine 5*/
		/*Ispituje se koji karakter u kombinaciji sa key0_sifra[5] daje key0list[0]*/
		for(s=0; s<256; s++)
		{
			key0_i_minus1 = ((key0list[0]<<8) ^ invcrc32tab[key0list[0]>>0x18]) ^ (s & 0xff);
			if((key0_i_minus1 & 0xff) == (key0_sifra[5] & 0xff))
			{
				lozinka[4] = s;		/*Pronadjen peti karakter lozinke*/

				/*Prelazi se na izracunavanje preostalih karaktera lozinke. Primenjivace se isti postupak kao kod
				/*trazenja lozinke duzine 4*/
				pom = key0_i_minus1;
				for(j=0; j<4; j++)
					pom = ((pom<<8) ^ invcrc32tab[pom>>0x18]) ^ 0x00;

				/*Sada se vrsi uporedjivanje sa pocetnom vrednoscu key0, i dobija se kompletna potencijalna lozinka*/
				lozinka[0] = (pom ^ 0x12345678) & 0xff;
				lozinka[1] = ((pom ^ 0x12345678) >> 8) & 0xff;
				lozinka[2] = ((pom ^ 0x12345678) >> 0x10) & 0xff;
				lozinka[3] = ((pom ^ 0x12345678) >> 0x18) & 0xff;

				/*Testira se da li je potencijalna lozinka zaista prava lozinka koja se koristi pri sifrovanju*/
				key0 = 0x12345678;
				key1 = 0x23456789;
				key2 = 0x34567890;
				for(j=0; j<5; j++)
				{
					key0 = (key0>>8) ^ crc32tab[((key0 & 0xff) ^ lozinka[j])&0xff];
					key1 = (key1 + (key0 & 0xff)) * 134775813 + 1;
					key2 = (key2>>8) ^ crc32tab[((key2 & 0xff) ^ (key1>>0x18)) & 0xff];
				}
				if(key0 == key0list[0] && key1 == key1list[0] && key2 == key2list[0])
				{
					printf("Koriscena je lozinka: %c%c%c%c%c\n", lozinka[0], lozinka[1], lozinka[2], lozinka[3], lozinka[4]);
					pronadjena_lozinka = 1;				/*Postavlja se da je pronadjena lozinka i izlazi se iz funkcije*/
					return;
				}
			}
		}
		return;
	}

	key1_i_minus1 = (key1_sifra[i] - 1) * 3645876429;	/*Dobijena je vrednost key1_sifra[i-1]+LSB(key0_sifra[i])*/

	/*Ako se bajtovi najvece tezine poklapaju, prelazi se na izracunavanje kompletne vrednosti key1_sifra[i-1],
	/*a u suprotnom se izlazi iz rekurzije*/
	if(((key1_i_minus1 & 0xff000000) != (key1_sifra[i-1] & 0xff000000)) ||
			(((key1_i_minus1 - 255) & 0xff000000) != (key1_sifra[i-1] & 0xff000000)))
		return;

	/*key1_sifra[i-1] se nalazi u intervalu [key1_i_minus1 - key1_i_minus1-255].
	/*Zato se uzimaju sve moguce vrednosti iz tog intervala i utvrdjuje se koja od njih daje odgovarajucu
	/*vrednost MSB(key1_sifra[i-2]), koja nam je vec poznata.
	/*Koristice se formula: key1_sifra[i-2] + LSB(key0_sifra[i-1]) = (key1_sifra[i-1] - 1) * 3645876429.
	/*Za svaku od 256 mogucnosti key1_sifra[i-1], se izracunava (key1_sifra[i-1] - 1) * 3645876429, a zatim 
	/*se uporedjuje dobijeni bajt najvece tezine sa MSB(key1_sifra[i-2]) i MSB(key1_sifra[i-2]+255). 
	/*Kad se dobije poklapanje, znaci da je dobijen kompletan key1_sifra[i-1]*/
	
	for(k=0; k<256; k++)
	{
		key1_i_minus2 = ((key1_i_minus1 - k) - 1) * 3645876429;	/*Za sve moguce key1_sifra[i-1] iz intervala 
																/*key1_i_minus1 - (key1_i_minus1-255),
																/*izracunava se vrednost key1_sifra[i-2]*/
		if((key1_i_minus2 & 0xff000000) == (key1_sifra[i-2] & 0xff000000) ||
				((key1_i_minus2 - 255) & 0xff000000) == (key1_sifra[i-2] & 0xff000000))
		{
			key1_sifra[i-1] = key1_i_minus1 - k;	/*Ako je pronadjeno poklapanje, dobijena je cela key1_sifra[i-1]*/
			/*Posto je LSB(key0_sifra[i]) = (key1_sifra[i] - 1) * 3645876429 -  key1_sifra[i-1], tj u nasem slucaju
			/*LSB(key0_sifra[i]) = key1_i_minus1 - key1_sifra[i-1], to znaci da je LSB(key0_sifra[i]) = k.*/
			key0_sifra[i] = k;
			key0_sifra[i] = key0_sifra[i] & 0xff;
			/*Prelazi se na izracunavanje vrednosti key1_sifra[i-2]*/
			key1_sifra5_rekurzija(i-1);
//				break;		/*Logicno je da ovde treba ubaciti komandu break; ali testiranjem je dobijeno da
							/*moze doci do vise poklapanja bajtova najvece tezine key1_sifra[i-2] i key1_i_minus2*/
		}
	}
}


void key1_sifra6_rekurzija(unsigned int i)
{
	/*Funkcija slicna funkciji key1_sifra5_rekurzija. Koristi se za pronalazenje lozinke duzine 5.
	/*Parametar pokazuje koji je element poslednji ceo poznat i pokazuje da se trazi kompletan key0_sifra[i-1]*/

	unsigned int key1_i_minus1;	/*vrednost promenljive key1_sifra[i-1]*/
	unsigned int key1_i_minus2;	/*vrednost promenljive key1_sifra[i-2]*/
	unsigned int key0_i_minus1;	/*vrednost promenljive key0list[-1]*/
	unsigned int key0_i_minus2;	/*vrednost promenljive key0list[-2]*/
	unsigned int key0, key1, key2;	/*promenljive koje ce se koristiti za proveravanje validnosti dobijene lozinke*/

	unsigned int j, k;			/*brojaci u petljama*/
	unsigned int pom;			/*pomocna promenljiva*/

	if(pronadjena_lozinka==1)
		return;		/*Ako je pronadjena lozinka, prekida se dalje trazenje*/

	if(i==4)		/*Ako su pronadjeni kompletni key1_sifra[3]-key1_sifra[6], izlazi se iz rekurzije i nastavlja se 
					/*sa daljim ispitivanjem, da li se ova nadjena lista key1_sifra[i] zaista formira pri sifrovanju*/
	{
		/*Poslednja dva karaktera lozinke se dobijaju direktno koriscenjem formule 
		/*key0[i-1] = (key0[i]<<8) xor invcrc32tab[MSB(key0[i])] xor lozinka[i-1], tj
		/*lozinka[i-1] = (key0[i]<<8) xor invcrc32tab[MSB(key0[i])] xor key0[i-1]. Kako je lozinka[i-1] dugacka 8 bitova,
		/*(key0[i]<<8) ne utice na rezultat, pa se moze izostaviti. To znaci da formula dobija oblik
		/*lozinka[i-1] = (invcrc32tab[MSB(key0[i])] xor key0[i-1]) & 0xff*/
		lozinka[duzina_lozinke-1] = (key0_sifra[6] ^ invcrc32tab[key0list[0]>>0x18]) & 0xff;	

		key0_i_minus1 = ((key0list[0]<<8) ^ invcrc32tab[key0list[0]>>0x18]) ^ (lozinka[duzina_lozinke-1] & 0xff);
		lozinka[duzina_lozinke-2] = (key0_sifra[5] ^ invcrc32tab[key0_i_minus1>>0x18]) & 0xff;
		
		key0_i_minus2 = ((key0_i_minus1<<8) ^ invcrc32tab[key0_i_minus1>>0x18]) ^ (lozinka[duzina_lozinke-2] & 0xff);

		/*Postavljaju se key0-key2 na pocetne vrednosti...*/
		key0 = 0x12345678;
		key1 = 0x23456789;
		key2 = 0x34567890;

		/*..kombinuju se sa prvim poznatim (proizvoljno uzetim) karakterima lozinke i menja se interni kljuc*/
		for(j=0; j<(duzina_lozinke-6); j++)
		{
			key0 = (key0>>8) ^ crc32tab[((key0 & 0xff) ^ lozinka[j])&0xff];
			key1 = (key1 + (key0 & 0xff)) * 134775813 + 1;
			key2 = (key2>>8) ^ crc32tab[((key2 & 0xff) ^ (key1>>0x18)) & 0xff];
		}

		pom = key0_i_minus2;
		for(j=0; j<4; j++)
			pom = ((pom<<8) ^ invcrc32tab[pom>>0x18]) ^ 0x00;

		/*Dobijen je key0[-6] . Sada se vrsi uporedjvanje sa key0 (vrednost dobijena kombinovanjem pocetnog internog 
		/*kljuca sa poznatih prvih duzina_lozinke-6 karaktera lozinke)*/
		pom = pom ^ key0;

		lozinka[duzina_lozinke-6] = pom & 0xff;
		lozinka[duzina_lozinke-5] = (pom >> 8) & 0xff;
		lozinka[duzina_lozinke-4] = (pom >> 0x10) & 0xff;
		lozinka[duzina_lozinke-3] = (pom >> 0x18) & 0xff;

		/*Testira se da li je potencijalna lozinka zaista prava lozinka koja se koristi pri sifrovanju*/
		key0 = 0x12345678;
		key1 = 0x23456789;
		key2 = 0x34567890;

		for(j=0; j<duzina_lozinke; j++)
		{
			key0 = (key0>>8) ^ crc32tab[((key0 & 0xff) ^ lozinka[j])&0xff];
			key1 = (key1 + (key0 & 0xff)) * 134775813 + 1;
			key2 = (key2>>8) ^ crc32tab[((key2 & 0xff) ^ (key1>>0x18)) & 0xff];
		}

		if(key0 == key0list[0] && key1 == key1list[0] && key2 == key2list[0])
		{
			printf("Koriscena je lozinka: ");
			for(j=0; j<duzina_lozinke; j++)
				printf("%c", lozinka[j]);		/*Stampa se pronadjena lozinka*/
			printf("\n");
			pronadjena_lozinka = 1;				/*Postavlja se da je pronadjena lozinka i izlazi se iz funkcije*/
			return;
		}

	return;
	}

	key1_i_minus1 = (key1_sifra[i] - 1) * 3645876429;	/*Dobijena je vrednost key1_sifra[i-1]+LSB(key0_sifra[i])*/

	/*Ako se bajtovi najvece tezine poklapaju, prelazi se na izracunavanje kompletne vrednosti key1_sifra[i-1],
	/*a u suprotnom se izlazi iz rekurzije*/
	if(((key1_i_minus1 & 0xff000000) != (key1_sifra[i-1] & 0xff000000)) ||
			(((key1_i_minus1 - 255) & 0xff000000) != (key1_sifra[i-1] & 0xff000000)))
		return;
	
	/*key1_sifra[i-1] se nalazi u intervalu [key1_i_minus1 - key1_i_minus1-255].
	/*Zato se uzimaju sve moguce vrednosti iz tog intervala i utvrdjuje se koja od njih daje odgovarajucu
	/*vrednost MSB(key1_sifra[i-2]), koja je vec poznata.
	/*Koristi se formula: key1_sifra[i-2] + LSB(key0_sifra[i-1]) = (key1_sifra[i-1] - 1) * 3645876429.
	/*Za svaku od 256 mogucnosti key1_sifra[i-1], se izracunava (key1_sifra[i-1] - 1) * 3645876429, a zatim 
	/*se uporedjuje dobijeni bajt najvece tezine sa MSB(key1_sifra[i-2]) i MSB(key1_sifra[i-2]+255). 
	/*Kad se dobije poklapanje, znaci da je dobijena kompletna key1_sifra[i-1]*/
	
	for(k=0; k<256; k++)
	{
		key1_i_minus2 = ((key1_i_minus1 - k) - 1) * 3645876429;	/*Za sve moguce key1_sifra[i-1] iz intervala 
																/*key1_i_minus1 - (key1_i_minus1-255),
																/*izracunava se vrednost key1_sifra[i-2]*/
		if((key1_i_minus2 & 0xff000000) == (key1_sifra[i-2] & 0xff000000) ||
				((key1_i_minus2 - 255) & 0xff000000) == (key1_sifra[i-2] & 0xff000000))
		{	
			key1_sifra[i-1] = key1_i_minus1 - k;	/*Ako je pronadjeno poklapanje, dobijena je cela key1_sifra[i-1]*/
			/*Posto je LSB(key0_sifra[i]) = (key1_sifra[i] - 1) * 3645876429 -  key1_sifra[i-1], tj u nasem slucaju
			/*LSB(key0_sifra[i]) = key1_i_minus1 - key1_sifra[i-1], to znaci da je LSB(key0_sifra[i]) = k.*/
			key0_sifra[i] = k;
			key0_sifra[i] = key0_sifra[i] & 0xff;
			/*Prelazi se na izracunavanje vrednosti key1_sifra[i-2]*/
			key1_sifra6_rekurzija(i-1);
//				break;		/*Logicno je da ovde treba ubaciti komandu break; ali testiranjem je dobijeno da
							/*moze doci do vise poklapanja bajtova najvece tezine key1_sifra[i-2] i key1_i_minus2*/
		}
	}
}

void pronadji_dugacku_lozinku(unsigned int duzina)
{
	/*Funkcija pomocu koje se dobijaju lozinke duze od 6 karaktera. Dobijeni parametar predstavlje duzinu lozinke*/
	/*Koristice se slican postupak kao kod pronalazenja lozinki duzine 6*/

	unsigned int key0, key1, key2;	/*vrednosti internog kljuca*/
	unsigned int pom;				/*pomocna promenljiva*/
	unsigned int i,j;				/*brojaci u petljama*/
	unsigned int key1_i_minus1;		/*vrednost promenljive key1list[i-1]*/
	unsigned int key2_i_minus1;		/*vrednost promenljive key2list[i-1]*/
	unsigned int key2_i_minus2;		/*vrednost promenljive key2list[i-2]*/

	/*Postavljaju se key0-key2 na pocetne vrednosti...*/
	key0 = 0x12345678;
	key1 = 0x23456789;
	key2 = 0x34567890;

	/*..kombinuju se sa prvim poznatim (proizvoljno uzetim) karakterima lozinke i menja se interni kljuc*/
	for(j=0; j<(duzina-6); j++)
	{
		key0 = (key0>>8) ^ crc32tab[((key0 & 0xff) ^ lozinka[j])&0xff];
		key1 = (key1 + (key0 & 0xff)) * 134775813 + 1;
		key2 = (key2>>8) ^ crc32tab[((key2 & 0xff) ^ (key1>>0x18)) & 0xff];
	}

	/*Moze se naci key2[-1], key1[-1] i key2[-2] iz formula: 
	/*key2[i-1] = (key2[i]<<8) xor invcrc32tab[MSB(key2[i])] xor MSB(key1[i]) i 
	/*key1[i-1] = ((key1[i]-1) * 3645876429) - LSB(key0[i])*/
	key2_i_minus1 = ((key2list[0]<<8) ^ invcrc32tab[key2list[0]>>0x18]) ^ ((key1list[0]>>0x18)&0xff);
	key1_i_minus1 = ((key1list[0]-1) * 3645876429) - (key0list[0] & 0xff);
	key2_i_minus2 = ((key2_i_minus1<<8) ^ invcrc32tab[key2_i_minus1>>0x18]) ^ ((key1_i_minus1>>0x18)&0xff);
	key1_sifra[6] = key1_i_minus1;	

	for(i=0; i<4; i++)
		key2_i_minus2 = ((key2_i_minus2<<8) ^ invcrc32tab[key2_i_minus2>>0x18]) ^ 0x00;

	/*Dobijen je key2[-5]. Sada se vrsi uporedjvanje sa key2 (vrednost dobijena kombinovanjem pocetnog internog kljuca
	/*sa poznatih prvih duzina-6 karaktera lozinke)*/
	pom = key2_i_minus2 ^ key2;

	/*Dobijene su potencijalne vrednosti MSB(key1[-4]), MSB(key1[-3]), MSB(key1[-2]), MSB(key1[-1]). One se stavljaju 
	/*u listu vrednosti key1_sifra*/
	key1_sifra[2] = (pom & 0xff) << 0x18;
	key1_sifra[3] = ((pom >> 8) & 0xff) << 0x18;
	key1_sifra[4] = ((pom >> 0x10) & 0xff) << 0x18;
	key1_sifra[5] = ((pom >> 0x18) & 0xff) << 0x18;
	
	/*Na osnovu poznate kompletne vrednosti key1_sifra[i] i poznatih MSB(key1_sifra[i-1]) i MSB(key1_sifra[i-2])
	/*izracunava se kompletna vrednost key1_sifra[i-1], nalaze se ostali potrebni elementi i proverava se da li je 
	/*to prava lozinka.*/ 
	key1_sifra6_rekurzija(6);

	if(pronadjena_lozinka == 1)
		return;			/*Ako je pronadjena lozinka duzine 6, izlazi se iz funkcije...*/

}