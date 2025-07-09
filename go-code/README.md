Here is your content in **Markdown (MD) format**, properly formatted and **unchanged in text**:

````md
# Go Code Explanation

This README provides the explanation of the Golang code.

The sample Go code is setting up a buffered channel of size 10 which takes an anonymous function as an argument:

```go
cnp := make(chan func(), 10)
````

At line 7, it spins up a loop which runs 4 times and makes 4 worker goroutines which execute the function stored by the channel.

At lines 14–15, it feeds the channel with the anonymous function body printing `"HERE1"`.

---

## QUESTIONS

### 1. Explaining how the highlighted constructs work?

**Ans:**

**Line 6:**

```go
cnp := make(chan func(), 10)
```

This line of code is called a buffered channel. A channel is used to communicate between goroutines.
A buffered channel provides the length of the channel (i.e. the number of objects it can hold).
This piece of code takes a function as an object and can hold 10 objects at once.

**Line 7–13:**

```go
for i := 0; i < 4; i++ {
    go func() {
        for f := range cnp {
            f()
        }
    }()
}
```

This piece of code spins up a loop which runs 4 times, and spins up worker goroutines and iterates through the channel for any objects it holds, and then executes the function that was in the channel.

Any function which has a `"go"` keyword in front of it executes in a separate thread (different from usual OS threads) managed by the Go runtime which is spawned from the main goroutine. These goroutines have no execution order and can execute randomly.

Here the goroutine is implemented as an anonymous function.

**Line 14:**

```go
cnp <- func() {
    fmt.Println("HERE1")
}
```

Here the channel earlier created is taking an anonymous function as a value which is printing `"HERE1"`.

---

### 2. Giving use-cases of what these constructs could be used for.

<!-- (No answer was provided in the original text.) -->

---

### 3. What is the significance of the for loop with 4 iterations?

The loop is creating 4 workers that will concurrently listen on the `cnp` channel.

---

### 4. What is the significance of `make(chan func(), 10)`?

Here it is creating a buffered channel. Unlike an unbuffered channel, a buffered channel doesn't block the execution until it is received by another goroutine.

---

### 5. Why is “HERE1” not getting printed?

`"HERE1"` is not printed because goroutines follow no execution pattern. They can execute anytime and don't block the main go routine from ending.
To fix this, we can utilise `WaitGroups`.

`WaitGroups` hold the execution of code until the number of goroutines added in `wg.Add(<number_of_goroutines>)` are finished executing.

---

### FIX:

```go
package main

import (
	"fmt"
	"sync"
)

func main() {
	wg := sync.WaitGroup{}

	wg.Add(4) // add waiting for 4 go routines
	cnp := make(chan func(), 10)
	for i := 0; i < 4; i++ {
		go func() {
			defer wg.Done() // only the first go routine ends, rest finish unsuccessfully but still marked as done
			for f := range cnp {
				f()
			}
		}()
	}
	cnp <- func() {
		fmt.Println("HERE1")
	}
	close(cnp) // close channel to prevent goroutines from starving

	wg.Wait() // wait for all goroutines to finish

	fmt.Println("Hello")
}
```

```
```
