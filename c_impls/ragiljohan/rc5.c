
#include<stdio.h>
#define w (32)
#define u (w/8)
#define b (16)
#define P ((unsigned) 0xb7e15163)
#define Q ((unsigned) 0x9e3779b9)
#define r (12)
#define t (2*(r+1))
#define c (b/u)
#define ROTL(x,y) (unsigned)((x<<((w-1)&y))|(x>>(w-((w-1)&y))))

unsigned S[t];
 
void round_key(unsigned K[c])
{
	int i,j,k;
	unsigned L[u],A,B;
	
	for(i=(c-1);i>=0;i--)
	{
		L[i] = K[(c - 1) - i];
	}
	
	S[0] = P;
	for(i=1;i<=t-1;i++)
	{
		S[i] = S[i-1] + Q ;
	}	
	i = j = A = B = 0;
	
	for(k=0;k<3*t;k++)
	{
		A = S[i] = ROTL((S[i] + A + B),3);
		B = L[j] = ROTL((L[j] + A + B),(A+B));
		i = (i+1)%t;
		j = (j+1)%c;
	}	
	
}
 
 
int main()
{
	int i;
	unsigned key_128[4];
	
	for(i=0;i<t;i++)
	{
		S[i] = 0;
	}
	
	for(i=0;i<c;i++)
	{
		printf("\nEnter the %d word of key",i+1);
		scanf("%u",&key_128[i]);

	}
	
	round_key(key_128);
	
	for(i=0;i<t;i++)
	{
		printf("\n%X",S[i]);
	}
		
	return 0;
}
