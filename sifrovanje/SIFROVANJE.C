/*	Matematicki fakultet		*/
/*	Diplomski - master rad		*/
/*	smer: racunarstvo i informatika	*/
/*	Zoran Tasic			*/
/*
/*	naziv rada: Analiza algoritma 	*/
/*	za sifrovanje u programu PKZIP	*/

/*Ovaj C program transformise nesifrovanu zip arhivu u sifrovanu zip arhivu.
/*Ulaz u program SIFROVANJE je kompresovana zip arhiva koja se dobija koriscenjem programa PKZIP 2.04 bez sifrovanja.
/*Program se iz komandne linije poziva sa argumentima nesifr_arhiva sifr_arhiva sifra,
/*gde nesifr_arhiva predstavlja ime arhive koja ce se sifrovati, sifr_arhiva je fajl koji se dobija kao izlaz iz programa,
/*a sifra je lozinka koji ce se koristiti za sifrovanje.
/*Izlaz iz programa SIFROVANJE bi trebalo da bude sifrovana zip arhiva koja ce moci da se desifruje pomocu
/*pkunzip -s sifra sifr_arhiva file.
/*Program SIFROVANJE radi samo za jedan ulazni file.*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

void update_keys(unsigned int* keys, char c);	/*funkcija koja azurira vrednosti key u zavisnosti od c*/
unsigned int crc32(unsigned int prev, char c);	/*funkcija koja vraca crc32 vrednost*/
void initcrc(void);						/*funkcija koja vrsi inicijalizaciju crc32tab i invcrc32tab*/
unsigned int calccrc32tab(char c);		/*funkcija koja se koristi za popunjavanje crc32tab i invcrc32tab*/
void init_keys(char *sifra);			/*funkcija koja inicijalizuje vrednosti key[0]-key[2] i kombinuje ih
										/*sa dobijenom lozinkom*/
int ucitaj4(FILE *);					/*funkcija koja ucitava int iz zadatog fajla i vraca taj procitani broj*/
short int ucitaj2(FILE *);				/*funkcija koja ucitava short int iz zadatog fajla i vraca taj procitani broj*/

void ispis2(FILE *, short int);			/*funkcija koja ispisuje zadati short int u zadati fajl*/
void ispis4(FILE *, int);				/*funkcija koja ispisuje zadati int u zadati fajl*/

unsigned int crc32tab[256];
unsigned int invcrc32tab[256];
unsigned int key[4];			/*key0-key3 sluze za sifrovanje*/


int main(int argc, char **argv)
{
	FILE *ulaz_file;			/*nesifrovana arhiva koja ulazi u program*/
	FILE *izlaz_file;			/*sifrovana zip arhive koja ce se formirati*/
	char *sifra;				/*lozinka pomocu koje ce se vrsiti sifrovanje*/

	unsigned char c;			/*sifrovani karakter koji ce sluziti za prepisivanje podataka iz jedne arhive u drugu*/
	unsigned char p;			/*nesifrovani karakter koji sluzi za prepisivanje podataka iz jedne arhive u drugu*/
	unsigned int crc;			/*crc32 value za dati file*/
	int file_size;				/*velicina kompresovanog fajla koji treba da se sifruje*/
	short i;					/*brojac u petljama*/
	unsigned int  sig, date_time, uncompr_size, ext_atr, ofset; 	/*deklaracije promenlivih koje ce se koristiti u programu*/
	short version, flags, compr_meth, name_len, extra_len, file_com_len, disk_start, int_atr, comm_len;


	if(argc!=4)
		{
			printf("Neodgovarajuci broj argumenata u komandnoj liniji\n");
			exit(1);			/*prekida se program*/
		}

	sifra=argv[3];				/*Iz komandne linije se ucitava lozinka pomocu koje ce se vrsiti sifrovanje*/

	ulaz_file=fopen(argv[1], "rb");		/*Otvara se fajl koji ce se sifrovati; otvara se samo za citanje*/

	izlaz_file=fopen(argv[2], "wb"); 	/*Kreira se fajl koji ce biti nova zip arhiva; otvara se za pisanje*/

	initcrc();					/*Inicijalizuje se crc32tab i invcrc32tab*/

	init_keys(sifra);			/*Inicijalizuje se key[0]-key[2] i kombinuje se se dobijenom lozinkom*/

	/*Ucitava se jedno po jedno polje (koje se ne menja) iz local headera i prepisuje se u izlaz_file*/
	/*u local file header se modifikuje polje Flags. Bit 0, koja oznacava da li ima/nema sifrovanja se sa 0 menja na 1*/
	/*u local file header se vrednost polja Compressed size povecava za 12, zbog dodavanja 11 random bajtova*/ 
	/*i 12. bajta koji predstavlja MSB(Crc32 value for file)*/ 
	/*Svi ostali podaci iz local file headers se samo prepisuju iz ulaz_file u izlaz_file*/	
   
	/*int sig -	signatura*/
	sig = ucitaj4(ulaz_file);	/*Ucitava se signatura*/
	ispis4(izlaz_file, sig);	/*i upisuje u izlazni fajl*/

	/*short version - verzija programa potrebna za dearhiviranje*/
	version = ucitaj2(ulaz_file);
	ispis2(izlaz_file, version);

	/*short flags*/
	flags = ucitaj2(ulaz_file);
	flags=flags|1;				/*Bit 00 se postavlja na 1, kao pokazatelj da je fajl sifrovan*/
	ispis2(izlaz_file, flags);

	/*short compr_meth - metod kompresije koji se koristi*/
	compr_meth = ucitaj2(ulaz_file);
	ispis2(izlaz_file, compr_meth);

	/*int	date_time - vreme i datum poslednje modifikacije fajla*/
	date_time = ucitaj4(ulaz_file);
	ispis4(izlaz_file, date_time);

	/*int crc - crc32 value za arhivirani fajl*/
	crc = ucitaj4(ulaz_file);
	ispis4(izlaz_file, crc);

	/*int file_size - velicina kompresovanog fajla (u bajtovima)*/
 	file_size = ucitaj4(ulaz_file);
	file_size=file_size+12;			/*Velicina kompresovanog fajla ce se povecati zbog*/
	ispis4(izlaz_file, file_size);	/*dodavanja encryption headera (12 bajtova)*/

	/*int uncompr_size - velicina nekompresovanog fajla (u bajtovima)*/
	uncompr_size = ucitaj4(ulaz_file);
	ispis4(izlaz_file, uncompr_size);

	/*short name_len - duzina naziva arhiviranog fajla*/
	name_len = ucitaj2(ulaz_file);
	ispis2(izlaz_file, name_len);

	/*short extra_len - duzina extra field*/
	extra_len = ucitaj2(ulaz_file);
	ispis2(izlaz_file, extra_len);

	if(name_len>0)
		{
		for(i=name_len;i>0;i--)		/*Prepisuje se ime arhiviranog fajla*/
			{
			fscanf(ulaz_file, "%c", &c);
			fprintf(izlaz_file, "%c", c);
			}
		}

	if(extra_len>0)
		{
		for(i=extra_len;i>0;i--)	/*Prepisuje se extra field (ako ga ima)*/
			{
			fscanf(ulaz_file, "%c", &c);
			fprintf(izlaz_file, "%c", c);
			}
		}


	/*Formira se encryption header: dodaje se 11 random generisanih bajtova...*/
	for(i=0; i<11; i++)
		{
			unsigned char k;
			k=rand();
			p=(unsigned char)(k&0xff);		/*Generise se jedan po jedan random bajt...*/
			c=p^key[3];						/*...sifruje se...*/
			update_keys(key,p);				/*...azurira se vrednost key[0]-key[2]...*/
			fprintf(izlaz_file, "%c", c);	/*...i upisuje se u sifrovanu arhivu*/
		}

	/*...a zatim se dodaje se 12 bajt koji predstavlja MSB(Crc32 value for file). Njega dobijamo iz local file headera-a*/
	p=(unsigned char)((crc>>24)&0xff);
	c=p^key[3];
	update_keys(key,p);
	fprintf(izlaz_file, "%c", c);


	/*Ucitava se jedan po jedan karakter, sifruje se i upisuje u zip_arhivu*/
	for(i=(file_size-12); i>0; i--)
		{
			fscanf(ulaz_file, "%c", &p);	/*Ucitava se jedan po jedan karakter iz ulazne arhive...*/
			c=p^key[3];						/*...sifruje se...*/
			update_keys(key, p);			/*...azurira se vrednost key0-key3...*/
			fprintf(izlaz_file, "%c", c);	/*...i upisuje se karakter u sifrovanu_arhivu*/
		}

	/*U central directory file header se menjaju polja Flags i Compressed size, ostali podaci iz
	/*central directory file header, kao i svi podaci iz End of central directory record (osim polja offset of
	/*cd wrt to starting disk) se samo prepisuju*/
		
	sig = ucitaj4(ulaz_file);				/*Prepisuje se signatura*/
	ispis4(izlaz_file, sig);
	
	version = ucitaj2(ulaz_file);			/*Verzija pkzip-a u kojoj je napravljena arhiva*/
	ispis2(izlaz_file, version);

	version = ucitaj2(ulaz_file);			/*Verzija pkzip-a potrebna za dearhiviranje*/
	ispis2(izlaz_file, version);

	flags = ucitaj2(ulaz_file);
	flags=flags|1;							/*Bit 00 se postavlja na 1, kao pokazatelj da je fajl sifrovan*/
	ispis2(izlaz_file, flags);

	compr_meth = ucitaj2(ulaz_file);		/*Metod kompresije koji se koristi*/
	ispis2(izlaz_file, compr_meth);

	date_time = ucitaj4(ulaz_file);			/*Vreme i datum zadnje modifikacije fajla*/
	ispis4(izlaz_file, date_time);
		
	crc = ucitaj4(ulaz_file);				/*crc32 value za arhivirani fajl*/
	ispis4(izlaz_file, crc);
		
	file_size = ucitaj4(ulaz_file);			/*Duzina kompresovanog fajla (u bajtovima)*/
	file_size=file_size+12;					/*Velicina kompresovanog fajla ce se povecati zbog*/
	ispis4(izlaz_file, file_size);			/*dodavanja encryption headera (12 bajtova)*/

	uncompr_size = ucitaj4(ulaz_file);		/*Velicina nekompresovanog fajla*/
	ispis4(izlaz_file, uncompr_size);

	name_len = ucitaj2(ulaz_file);			/*Duzina naziva arhiviranog fajla*/
  	ispis2(izlaz_file, name_len);		

	extra_len = ucitaj2(ulaz_file);			/*Duzina extra field*/
	ispis2(izlaz_file, extra_len);

	/*short file_com_len - duzina polja za komentare*/
	file_com_len = ucitaj2(ulaz_file);
	ispis2(izlaz_file, file_com_len);

	/*short disk_start - broj diska na kome se nalazi fajl*/
	disk_start = ucitaj2(ulaz_file);
	ispis2(izlaz_file, disk_start);

	/*short int_atr - interni atributi fajla*/
	int_atr = ucitaj2(ulaz_file);
	ispis2(izlaz_file, int_atr);

	/*int ext_atr - eksterni atributi fajla*/
	ext_atr = ucitaj4(ulaz_file);
	ispis4(izlaz_file, ext_atr);

	/*int ofset - ofset of local header*/
	ofset = ucitaj4(ulaz_file);
	ispis4(izlaz_file, ofset);

	if(name_len>0)
		{
		for(i=name_len; i>0; i--)			/*Prepisuje se ime arhiviranog fajla*/
			{
			fscanf(ulaz_file, "%c", &c);
			fprintf(izlaz_file, "%c", c);
			}
		}

	if(extra_len>0)
		{
		  for(i=extra_len; i>0; i--)		/*Prepisuje se extra field (ako ga ima)*/
			{
			fscanf(ulaz_file, "%c", &c);
			fprintf(izlaz_file, "%c", c);
			}
		}

	if(file_com_len>0)
		{
			for(i=file_com_len; i>0; i--)	/*Prepisuje se file comment (ako ga ima)*/
			{
			fscanf(ulaz_file, "%c", &c);
			fprintf(izlaz_file, "%c", c);
			}
		}

	/*Prepisuju se podaci iz end of central directory record.*/
	/*Prvih 6 polja, ukupne duzine 16 bajtova su isti pa se samo prepisuju*/
	for(i=16;i>0;i--)
		{
			fscanf(ulaz_file, "%c", &c);
			fprintf(izlaz_file, "%c", c);
		}

	/*Polje offset of cd wrt to starting disk se povecava za 12 zbog dodatih 12 random bajtova*/
	ofset = ucitaj4(ulaz_file);
	ofset=ofset+12;
	ispis4(izlaz_file, ofset);

	/*short comm_len - duzina polja za komentare*/
	comm_len = ucitaj2(ulaz_file);
	ispis2(izlaz_file, comm_len);

	if(comm_len>0)
		{
			for(i=comm_len; i>0; i--)		/*Prepisuje se ZIP file comment (ako ga ima)*/
			{
			fscanf(ulaz_file, "%c", &c);
			fprintf(izlaz_file, "%c", c);
			}
		}



	fclose(ulaz_file);						/*Zatvara se ulazna arhiva*/

	fclose(izlaz_file);						/*Zatvara se izlazna arhiva*/
	return 0;
}

void update_keys(unsigned int *key, char c)	/*Funkcija za azuriranje sadrzaja key[0]-key[3]*/
{
	unsigned int temp;
	key[0]=crc32((key[0]), c);
	key[1]=((key[1])+(key[0]&0xff));
	key[1]=(((key[1]*134775813u))+ 1);
	key[2]=crc32((key[2]),(char) ((key[1]>>24)&0xff));
	temp = key[2]|3;
	key[3]=((temp*(temp^1))>>8)&0xff;
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


void initcrc(void)							/*Pocetno punjenje tabela crc32tab i invcrc32tab*/
{
	unsigned int val;
	int i;

	for (i=0 ; i<256 ; i++)
	{
	val = calccrc32tab((char) i);
	crc32tab[i]=val;
	invcrc32tab[(int)(val>>24)] = (val<<8) ^ i;
	}
}


unsigned int crc32(unsigned int prev, char c)	/*Funkcija koja izracunava crc32 vrednost koja se koristi*/
{												/* za azuriranje vrenosti key0-key3*/
	unsigned int a,b,d,f, crc_v;
	a=prev>>8;
	b=prev&0xff;
	d=(b^(short)c)&0xff;
	f=crc32tab[d];
	crc_v=a^f;
	return crc_v;
}

void init_keys(char *sifra)
{
	/*Inicijalizuje se key[0]-key[2] i kombinuje se sa dobijenom sifrom*/
	key[0]=0x12345678L;
	key[1]=0x23456789L;
	key[2]=0x34567890L;
	while (*sifra!='\0')
		update_keys(key, *sifra++);

}

int ucitaj4(FILE * ulaz_file)
{
	int c=0,t=0;
	fscanf(ulaz_file,"%c",&c);
	t=c;	    					/*U prvom koraku cita bajt koji ce biti bajt najmanje tezine u broju*/
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
	t=c;	    					/*U prvom koraku cita bajt koji ce biti bajt najmanje tezine u broju*/
	fscanf(ulaz_file,"%c",&c);
	t=((c<<8)&0xff00) | t;
	return t;
}

void ispis2(FILE * izlaz_file, short int t)
{
	int c;
	c=t&0xff;
	fprintf(izlaz_file,"%c", c);  	/*Prvo se ispisuje bajt najmanje tezine*/
	c=(t>>8)&0xff;
	fprintf(izlaz_file,"%c", c);
}

void ispis4(FILE * izlaz_file, int t)
{
	int c;
	c=t&0xff;
	fprintf(izlaz_file,"%c", c);  	/*Prvo se ispisuje bajt najmanje tezine*/
	c=(t>>8)&0xff;
	fprintf(izlaz_file,"%c", c);
	c=(t>>16)&0xff;
	fprintf(izlaz_file,"%c", c);
	c=(t>>24)&0xff;
	fprintf(izlaz_file,"%c", c);
}
