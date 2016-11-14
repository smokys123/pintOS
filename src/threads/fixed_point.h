#define F (1 << 14)              //fixed point 1
#define INT_MAX ( (1 << 31)-1 )
#define INT_MIN ( -(1 << 31) )

int int_to_fp(int n);            //integer(이하 INT)를 fixed point(이하 FP)로 전환
int fp_to_int_round(int x);      //FP를 INT로 반올림해서 전환
int fp_to_int(int x);            //FP를 INT로 버림해서 전환
int add_fp(int x, int y);        //FP끼리의  덧셈
int add_mixed(int x, int n);     //FP와 INT의 덧셈
int sub_fp(int x, int y);        //FP끼리의 뺄셈   
int sub_mixed(int x, int n);     //FP와 INT의 뺄셈  
int mult_fp(int x, int y);       //FP끼리의 곱셈  
int mult_mixed(int x, int n);    //FP와 INT의 곱셈  
int div_fp(int x, int y);        //FP끼리의 나눗셈  
int div_mixed(int x, int n);     //FP와 INT의 나눗셈

int int_to_fp(int n){
  return n*F;
}

int fp_to_int_round(int x){
  if(x >= 0)
    return (x+F/2)/F;
  else
    return (x-F/2)/F;
}

int fp_to_int(int x){
  return x/F;
}

int add_fp(int x, int y){
  return x+y;
}

int add_mixed(int x, int n){
  return x + int_to_fp(n);
}

int sub_fp(int x, int y){
  return x-y;
}

int sub_mixed(int x , int n){
  return x - int_to_fp(n);
}

int mult_fp(int x, int y){
  return ((int64_t)x) * y/F;
}

int mult_mixed(int x, int n){
  return x*n;
}

int div_fp(int x, int y){
  return ((int64_t)x) * F/y;
}

int div_mixed(int x, int n){
  return x/n;
}
