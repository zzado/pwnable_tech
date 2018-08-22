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

                2. 1번의 조건이 만족하지 않는 경우, 일단 unsorted bin에서 청크 제거 -> 이과정에서 사이즈나 chain유효 검사가 없어서 unsortedbin attack 발생
              ```c
              while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
              {
              bck = victim->bk;
              ...
              /* remove from unsorted list */
              unsorted_chunks (av)->bk = bck; // 우리가 수정한 bck가 들어가자너!
              bck->fd = unsorted_chunks (av);
              ```
                3. 이후 2번에서 unsorted bin으로 부터 제거된 chunk는 해당 사이즈에 맞는 bin으로 들어가게됨!(smallbin or largebin // fastbin x)

                4. 1번과정 또는 3번과정을 거치면 unsortedbin의 다음 청크에 대하여 똑같은 루틴 수행

            - unsortedbin attack? unsorted bin의 마지막 chunk의 bk를 수정하여 원하는곳에 main_arena.top주소를 적을 수 있다!
 
        5. top chunk
            - 위의 과정을 거치면서 chunk가 재할당되지 못한경우(_int_malloc에서 return이 안된경우!) top chunk에서 잘라서 반환해준다.
           - top chunk 사이즈가 모자라면? sysmalloc() 호출!


         












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
### 1.1.3. bins


## 1.2 glibc2.27 (Ubuntu 18.04) 

