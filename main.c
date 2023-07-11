#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include<openssl/evp.h>

#define MAXLEN 256

void md5(const char *in, char *out){
	int inlen = strlen(in);
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned char md[EVP_MAX_MD_SIZE];
	int mdlen;
	EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
	EVP_DigestUpdate(ctx, in, inlen);
	EVP_DigestFinal_ex(ctx, md, &mdlen);
	EVP_MD_CTX_free(ctx);
	for(int i = 0; i < mdlen; ++i)
		sprintf(&out[i * 2], "%02x", md[i]);
 }

int main(int argc, char *argv[]){
	int verbose = 0, quiet = 0;
	if(argc == 4 && argv[3][1] == 'v')++verbose;
	if(argc == 4 && argv[3][1] == 'q')++quiet;
	if(argc < 3){
		printf("./program details.txt passwords.txt [-vq]\n");
		printf("-v prints every attempt, -q hides progress messages\n");
		printf("detail file contents:\nuser=%%s\\n\nrealm=%%s\\n\n");
		printf("method=%%s\\n\nuri=%%s\\n\nnonce=%%s\\n\nresponse=%%s\\n\n");
		return 1;
	}
	FILE *detailFile = fopen(argv[1], "r");
	if(!detailFile){
		printf("Failed to open detail file.\n");
		return 1;
	}
	FILE *passFile = fopen(argv[2], "r");
	if(!passFile){
		printf("Failed to open password file.\n");
		return 1;
	}
	char user[MAXLEN], method[MAXLEN], realm[MAXLEN], nonce[MAXLEN];
	char uri[MAXLEN], capResponse[MAXLEN];
	fscanf(detailFile, "user=%s\nrealm=%s\nmethod=%s\n", user, realm, method);
	fscanf(detailFile, "uri=%s\nnonce=%s\nresponse=%s\n", uri, nonce, capResponse);
	fclose(detailFile);
	char pass[MAXLEN], ha1in[MAXLEN], ha1[MAXLEN], ha2in[MAXLEN];
	char ha2[MAXLEN], responseIn[MAXLEN], response[MAXLEN];
	time_t stTime = time(0);
	for(unsigned long i = 0; fgets(pass, MAXLEN, passFile); ++i){
		size_t passLen = strlen(pass);
		if(passLen > 0 && pass[passLen - 1] == '\n')
			pass[passLen - 1] = '\0';
		snprintf(ha1in, MAXLEN, "%s:%s:%s", user, realm, pass);
		md5(ha1in, ha1);
		snprintf(ha2in, MAXLEN, "%s:%s", method, uri);
		md5(ha2in, ha2);
		snprintf(responseIn, MAXLEN, "%s:%s:%s", ha1, nonce, ha2);
		md5(responseIn, response);
		if(!strcmp(response, capResponse)){
			printf("%lu PASSWORD FOUND! %s\n", i, pass);
			break;
		}
		else if(verbose)
			printf("%lu trying: %s\tresponse: %s\n", i, pass, response);
		if(!quiet && i % 100000 == 0){
			time_t tm = time(0) - stTime;
			if(tm)printf("%lu tries in %d:%d, %d tries/s\n", i, tm/60, tm, i / tm);
		}
	}
	fclose(passFile);
	return 0;
}
