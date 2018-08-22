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
    
    - 첫 malloc()시 checked_request2size()를 통해 align에 맞게 사이즈 변경하고 sysmalloc() 호출
    
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

    - 다음과 같은 순으로 할당해줄 공간을 체크함.
      1. fastbin  
          - global_max_fast 이하 size
          - fastbin index에 맞지 않는 size의 chunk가 bin에 존재할경우 corruption 뜸
          - fastbin은 어떠한 경우에도 merge되지 않음!
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
          - fastbin에 


         


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

