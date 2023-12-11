---
layout: default
title: "0CTF/TCTF 2023 how2compile"
date: 2023-12-11
permalink: /how2compile/
categories: ctf reversing rustc compiler
---

This week, my team DiceGang played 0CTF/TCTF, and I had time to look at one challenge - `how2compile`, reversing a custom `rustc_driver` binary. Having contributed to Rustc before, I was particularly interested in this challenge, and the experience definitely helped me save some time identifying the program's workings.

<!--more-->

With a quick look at the binary, we can identify it as an unoptimised Rust binary. We know it's unoptimised as there are many trivially inlinable function calls such as `String::new`. Skimming through the function calls in `main`, we can spot calls to `rustc_interface::run_compiler`. This lets us identify the program as a custom `rustc_driver` - a program using the Rust compiler as a library to do something other than compile code.

The `main` function is very verbose, but luckily we can fairly quickly identify many parts of it as actually being based on the [example for `rustc_driver` programs](https://github.com/rust-lang/rustc-dev-guide/blob/master/examples/rustc-driver-example.rs).

We'll go through the snippets that differ here.
```c
int64_t arr1[0xc]
arr1[0] = 0xa
arr1[1] = 0xb
/ * ... */
arr1[0xb] = 0xbc
void hashset1
<std::collections::hash::set::HashSet<T> as core::convert::From<[T; N]>>::from(&hashset1, &arr1)
```
We begin by initializing some `HashSet` with 12 small, constant numbers.

```c
int32_t arr2[0x30]
arr2[0x18] = 0x5e
/* ... */
arr2[0x2f] = 0x51
int32_t rax = arr2[0x19]
arr2[0] = arr2[0x18]
arr2[1] = rax
int32_t rax_1 = arr2[0x1b]
arr2[2] = arr2[0x1a]
/* ... */
void hashset2
<std::collections::hash::set::HashSet<T> as core::convert::From<[T; N]>>::from(&hashset2, &arr2)
```
We then initialize a second hashset from a larger `int` array. Interestingly, the contents of the array seem to be repeated twice - the second half is initialized, then copied element by element into the first half.

```c
std::fs::read_to_string::h51d0b2090f032cc2(&result_flag, "flag.txttask2.rsassertion failed: 0 < pointee_size && pointe…")
struct String flag_string
core::result::Result<T,E>::expect::had9b02aeb4d59a7b(&flag_string, &result_flag, "flag.txt not foundcode:\nread failed[END]1. print HIR\n2. pr…", 0x12, &data_17a640)
struct FormatArgs fargs
core::fmt::Arguments::new_const::h3044214c9419b994(&fargs, &data_17a658, 1)
std::io::stdio::_print::hd1fcef799e49a613(&fargs)
int64_t stdin = std::io::stdio::stdin::h3540ac1498ff7c37()
struct String s1
alloc::string::String::new::hce061750ca86c9fc(&s1)
struct String s2
alloc::string::String::new::hce061750ca86c9fc(&s2)
```
Note: Decompilers don't show Rust strings very well as they expect null-terminated strings, We can usually tell the correct string length by either following the pointer to the string in static memory, where the length will be along side it, or it will be passed as a third parameter.

We can see here that `flag.txt` is read into `flag_string`, with a panic if this fails. We then print out `code:` (the string at `0x17a658`, before preparing two `String`s and getting a `stdin` handle.
```c
while (true) {
    void result
    std::io::stdio::Stdin::read_line::h7f31184e8b6f22d1(&result, &stdin, &s2)
    core::result::Result<T,E>::expect::h598459ace5542077(&result, "read failed[END]1. print HIR\n2. print MIR\n3. print LIR\nno…")
    int64_t rax_14
    int64_t rdx_3
    rax_14, rdx_3 = <alloc::string::String...f::Deref>::deref::h68c3eeea78c9b914(&s2)
    char* ptr_2
    int64_t len
    ptr_2, len = core::str::<impl str>::trim::h648d63e1c658b1e7(rax_14, rdx_3)
    struct str_slice inp
    inp.ptr = ptr_2
    inp.len = len
    if ((core::cmp::impls::<imp...<&B> for &A>::eq::h6f48b5bdb4acb6ad(&inp, &data_17a680) & 1) != 0) {
        break
    }
    char* sptr
    int64_t slen
    sptr, slen = <alloc::string::String...f::Deref>::deref::h68c3eeea78c9b914(&s2)
    <alloc::string::String...tr>>::add_assign::h7b457dd831cbb4e9(&s1, sptr, slen)
    alloc::string::String::clear::he365718207622af4(&s2)
}
```
We then enter an input reading loop. `s2`takes our input, the string is dereferenced to get an `&str`, then `.trim()`'d to get another `&str`. It's compared to `[END]` (which causes it to break) - otherwise, the input is appended to `s1`.

We then print out 3 menu items (`print HIR, print MIR, print LIR`), before prompting the user for a number.
Following this there is a lot of code that is identical at a glance to the example, so we'll skip ahead.
```c
void var_b60
memcpy(&var_b60, &var_2760, 0x9a8)
int32_t* var_1b8 = &menu_choice
void* var_1b0 = &hashset2
struct String* var_1a8 = &s1
void* var_1a0 = &hashset1
struct String* var_198 = &flag_string
rustc_interface::interface::run_compiler::h2f3ba037609242a8(&var_b60, &var_1b8)
```
Luckily the `rustc` docs are easily accessible, so we can check the signature of `run_compiler` [here](https://doc.rust-lang.org/stable/nightly-rustc/rustc_interface/interface/fn.run_compiler.html). `var_b60` is therefore a large `Config` variable. The second argument is a closure - once compiled, the second argument is simply a struct containing the borrowed variables. We'll name this `RunCompilerClosure` and identify the fields:
```c
struct RunCompilerClosure cls
cls.menu_choice = &menu_choice
cls.hashset2 = &hashset2
cls.code = &s1
cls.hashset1 = &hashset1
cls.flag_string = &flag_string
```
Following this, there is a long chain of uninlined callbacks and closures. I will skip ahead to the function that looks most obviously like the main body of the challenge and the closure that was originally passed in.

```c
int64_t task2::main::{{closure}}::{{closure}}::{{closure}}::h22fdd4a9fe0a0f95(struct RunCompilerClosure* closure, struct Compiler* compiler)
	int32_t rax_1 = *closure->menu_choice
	int64_t rax_27
	if (rax_1 == 1) {
```
We begin by checking the menu option chosen against 1, 2 or 3. We'll look at each in order.

# 1 (Print HIR)
The part names are quite misleading - they don't actually print HIR/MIR/LIR. (They did in the original version of the challenge, but that allowed players to easily `include_str!("flag.txt")` and read the flag with no reversing required.)

We can see that the program begins by calling [`Map::items`](https://doc.rust-lang.org/stable/nightly-rustc/rustc_middle/hir/map/struct.Map.html#method.items) and iterating over it:
```c
    items, rdx = rustc_middle::hir::map::Map::items::h2cbcff9b8de429f9(compiler)
    int64_t items_iter
    int64_t rdx_1
    items_iter, rdx_1 = <I as core::iter::trai...ator>::into_iter::hffdf89b7c3b325ed(items)
    int64_t items_iter_1 = items_iter
    int64_t var_4c8_1 = rdx_1
    while (true) {
        int32_t option_item_id = <core::iter::adapters:...:Iterator>::next::h6515ab5f42f2706f(&items_iter_1)
        rax_24 = 1
        if (option_item_id == 0xffffff01) {
            rax_24 = 0
        }
        if (rax_24 == 0) {
            break
        }
```
We then use the `ItemId` to get an item (unfortunately my decompiler didn't manage to demangle imported names) - 
```c
        struct Item* rax_25_1 = _RNvMs0_NtNtCsdXL367Ff...2rustc_middle3hir3mapNtB5_3Map4item(compiler, zx.q(option_item_id))
        if (zx.q(rax_25_1->field_10) == 0xc) {
            int128_t field_30 = rax_25_1->field_30
            int128_t field_20 = rax_25_1->field_20
```
With a bit of an educated guess (can be confirmedd by debugging), we can guess that `0xc` is checking the enum tag of the items `kind`. We can check the [docs](https://doc.rust-lang.org/stable/nightly-rustc/rustc_hir/hir/enum.ItemKind.html) an see that `0xc` most likely corresponds with the 12th enum variant - `Struct`. This assertion is strengthened by following calls to `VariantData::fields`.

We initialise a new empty hashset, then begin iterating over the fields.

```c
            std::collections::hash...:HashSet<T>::new::hbae348019a52a5a0(&var_490)
            uint32_t* fields
            int64_t rdx_8
            fields, rdx_8 = rustc_hir::hir::VariantData::fields::hce9c2fedd42aa525(&variant_data)
            int64_t fields_iter
            int64_t rdx_9
            fields_iter, rdx_9 = core::slice::iter::<im...&[T]>::into_iter::he4423b2ace9220cc(fields, rdx_8)
            int64_t fields_iter_1 = fields_iter
            int64_t var_458_1 = rdx_9
            while (true) {
                struct Field* field_1 = <core::slice::iter::It...:Iterator>::next::hd5e8bf5b69f7deff(&fields_iter_1)
                int64_t rax_29 = 1
                if (field_1 == 0) {
                    rax_29 = 0
                }
                if (rax_29 == 0) {
                    break
                }
                int64_t span = field_1->span
                int32_t lo = rustc_span::<impl rust...oding::Span>::lo::h50d0dd16e390b7bb(span)
                std::collections::hash...Set<T,S>::insert::h4eaf8c015854981d(&var_490, lo, rustc_span::<impl rust...oding::Span>::hi::h592a7adea3a02d13(span))
            }
```
For each field, we take some `span` and take its `lo` and `high` part (byte positions in the source code). A `(lo, hi)` tuple is then added to the hashset. Finally, this hashset is compared against `hashset2` from `main` function:
```c
if ((<std::collections::has...::PartialEq>::eq::h707bc4966f890005(&var_490, closure->hashset2) & 1) != 0) {`
If they match, one third of `flag.txt` is printed.

Lets try and solve this part of the challenge. We need to feed the 'compiler' a struct definition where each field has its low and high positions at specific locations. First we'll needd to debug the binary to find the constant field positions. We'll break just before the hashset initialisation.
`rustup run nightly-2023-11-03 gdb ./task -ex 'pie b 0x11411a' -ex 'r'` (I'm using GEF, a GDB extension. `pie b` allows me to place breakpoints on a PIE binary before it starts).
We know the array is 48 elements long, but only the first 24 matter: `x/24d $rsi` with some formatting by hand gives us the positions `[94, 97, 51, 54, 66, 69, 105, 108, 120, 123, 130, 150, 156, 159, 164, 167, 171, 174, 21, 41, 177, 185, 78, 81]`.
We can see some are only 3 bytes - too short to define a field name?
In fact, we can just create a tuple struct. `struct T((), (), ())` gives us 3 2-length fields, and we can just add spaces to make them the right length. Let's script generating a solution to this challenge.

```py
src = ""

# Part 1
bytes = [...]
tuples = sorted([(bytes[i], bytes[i+1]) for i in range(0, len(bytes), 2)])

src += "struct T("
for lo, hi in tuples:
    src = src.ljust(lo, " ")
    src += "("
    padding = hi - lo - 2
    src += " " * padding
    src += "),"
src += ");"
print(src)
```
If we enter the resulting `struct T(            (                  ),         ( ),           ( ),        ( ),            ( ),       ( ),           ( ),      (                  ),     ( ),    ( ),   ( ),  (      ),);
` into the binary, then choose 'Print HIR' the binary will print out the end of our test flag!

# 2 (Print MIR)

Returning to part 2, we can see this part is a little more complex. There's a lot of retrieving fields thousands of bytes deep into the compiler struct, and `transmuting` and queries, all of which is very opaque without type or layout info. Luckily, there's a clue further ahead - `rustc_middle::mir::pretty::write_mir_fn::h14fc5c500591ae6a` is called. This dumps out a function's MIR into a human-readable format.
With some inference, we can see that this is iterating over every function in the binary and dumping their MIR. There is a static string, decoded at runtime, containing an MIR dump, which is compared against our input.

```rs
fn main() -> () {
    let mut _0: ();
    let _1: std::io::Stdin;
    let mut _3: usize;
    let mut _4: std::result::Result<usize, std::io::Error>;
    let mut _5: &std::io::Stdin;
    let mut _6: &mut std::string::String;
    let _7: &str;
    let _9: &str;
    let _10: &str;
    let mut _11: &std::string::String;
    let mut _12: usize;
    let mut _13: u8;
    let _14: usize;
    let mut _15: usize;
    let mut _16: bool;
    let mut _17: u8;
    let _18: usize;
    let mut _19: usize;
    let mut _20: bool;
    let mut _21: u8;
    let _22: usize;
    let mut _23: usize;
    let mut _24: bool;
    let mut _25: u8;
    let _26: usize;
    let mut _27: usize;
    let mut _28: bool;
    let mut _29: u8;
    let _30: usize;
    let mut _31: usize;
    let mut _32: bool;
    let mut _33: u8;
    let _34: usize;
    let mut _35: usize;
    let mut _36: bool;
    let mut _41: (u8, u8, u8, u8);
    let mut _42: u8;
    let _43: usize;
    let mut _44: usize;
    let mut _45: bool;
    let mut _46: u8;
    let _47: usize;
    let mut _48: usize;
    let mut _49: bool;
    let mut _50: u8;
    let _51: usize;
    let mut _52: usize;
    let mut _53: bool;
    let mut _54: u8;
    let _55: usize;
    let mut _56: usize;
    let mut _57: bool;
    let mut _58: u8;
    let mut _59: (u8, bool);
    let mut _60: u8;
    let mut _61: (u8, bool);
    let mut _62: u16;
    let mut _63: u16;
    let mut _64: u16;
    let mut _65: (u16, bool);
    let mut _66: u8;
    let mut _67: (u8, bool);
    let _68: ();
    let mut _69: std::fmt::Arguments<'_>;
    let mut _70: &[&str];
    scope 1 {
        debug reader => _1;
        let mut _2: std::string::String;
        scope 2 {
			debug buf => _2;
			scope 3 {
				let _8: &[u8];
				scope 4 {
					debug flag => _8;
					let _37: u8;
					let _38: u8;
					let _39: u8;
					let _40: u8;
					scope 5 {
						debug a => _37;
						debug b => _38;
						debug c => _39;
						debug d => _40;
						let mut _71: &[&str; 1];
					}
				}
			}
        }
    }

    bb0: {
        _1 = std::io::stdin() -> [return: bb1, unwind continue];
    }

    bb1: {
        _2 = std::string::String::new() -> [return: bb2, unwind continue];
    }

    bb2: {
        _5 = &_1;
        _6 = &mut _2;
        _4 = std::io::Stdin::read_line(move _5, _6) -> [return: bb3, unwind: bb37];
    }

    bb3: {
        _7 = const "read failed";
        _3 = std::result::Result::<usize, std::io::Error>::expect(move _4, _7) -> [return: bb4, unwind: bb37];
    }

    bb4: {
        _11 = &_2;
        _10 = <std::string::String as std::ops::Deref>::deref(move _11) -> [return: bb5, unwind: bb37];
    }

    bb5: {
        _9 = core::str::<impl str>::trim(_10) -> [return: bb6, unwind: bb37];
    }

    bb6: {
        _8 = core::str::<impl str>::as_bytes(_9) -> [return: bb7, unwind: bb37];
    }

    bb7: {
        _12 = Len((*_8));
        switchInt(move _12) -> [10: bb8, otherwise: bb34];
    }

    bb8: {
        _14 = const 0_usize;
        _15 = Len((*_8));
        _16 = Lt(_14, _15);
        assert(move _16, "index out of bounds: the length is {} but the index is {}", move _15, _14) -> [success: bb9, unwind: bb37];
    }

    bb9: {
        _13 = (*_8)[_14];
        switchInt(move _13) -> [102: bb10, otherwise: bb35];
    }

    bb10: {
        _18 = const 1_usize;
        _19 = Len((*_8));
        _20 = Lt(_18, _19);
        assert(move _20, "index out of bounds: the length is {} but the index is {}", move _19, _18) -> [success: bb11, unwind: bb37];
    }

    bb11: {
        _17 = (*_8)[_18];
        switchInt(move _17) -> [108: bb12, otherwise: bb35];
    }

    bb12: {
        _22 = const 2_usize;
        _23 = Len((*_8));
        _24 = Lt(_22, _23);
        assert(move _24, "index out of bounds: the length is {} but the index is {}", move _23, _22) -> [success: bb13, unwind: bb37];
    }

    bb13: {
        _21 = (*_8)[_22];
        switchInt(move _21) -> [97: bb14, otherwise: bb35];
    }

    bb14: {
        _26 = const 3_usize;
        _27 = Len((*_8));
        _28 = Lt(_26, _27);
        assert(move _28, "index out of bounds: the length is {} but the index is {}", move _27, _26) -> [success: bb15, unwind: bb37];
    }

    bb15: {
        _25 = (*_8)[_26];
        switchInt(move _25) -> [103: bb16, otherwise: bb35];
    }

    bb16: {
        _30 = const 4_usize;
        _31 = Len((*_8));
        _32 = Lt(_30, _31);
        assert(move _32, "index out of bounds: the length is {} but the index is {}", move _31, _30) -> [success: bb17, unwind: bb37];
    }

    bb17: {
        _29 = (*_8)[_30];
        switchInt(move _29) -> [123: bb18, otherwise: bb35];
    }

    bb18: {
        _34 = const 9_usize;
        _35 = Len((*_8));
        _36 = Lt(_34, _35);
        assert(move _36, "index out of bounds: the length is {} but the index is {}", move _35, _34) -> [success: bb19, unwind: bb37];
    }

    bb19: {
        _33 = (*_8)[_34];
        switchInt(move _33) -> [125: bb20, otherwise: bb35];
    }

    bb20: {
        _43 = const 5_usize;
        _44 = Len((*_8));
        _45 = Lt(_43, _44);
        assert(move _45, "index out of bounds: the length is {} but the index is {}", move _44, _43) -> [success: bb21, unwind: bb37];
    }

    bb21: {
        _42 = (*_8)[_43];
        _47 = const 6_usize;
        _48 = Len((*_8));
        _49 = Lt(_47, _48);
        assert(move _49, "index out of bounds: the length is {} but the index is {}", move _48, _47) -> [success: bb22, unwind: bb37];
    }

    bb22: {
        _46 = (*_8)[_47];
        _51 = const 7_usize;
        _52 = Len((*_8));
        _53 = Lt(_51, _52);
        assert(move _53, "index out of bounds: the length is {} but the index is {}", move _52, _51) -> [success: bb23, unwind: bb37];
    }

    bb23: {
        _50 = (*_8)[_51];
        _55 = const 8_usize;
        _56 = Len((*_8));
        _57 = Lt(_55, _56);
        assert(move _57, "index out of bounds: the length is {} but the index is {}", move _56, _55) -> [success: bb24, unwind: bb37];
    }

    bb24: {
        _54 = (*_8)[_55];
        _41 = (move _42, move _46, move _50, move _54);
        _37 = (_41.0: u8);
        _38 = (_41.1: u8);
        _39 = (_41.2: u8);
        _40 = (_41.3: u8);
        _59 = CheckedAdd(_37, _38);
        assert(!move (_59.1: bool), "attempt to compute `{} + {}`, which would overflow", _37, _38) -> [success: bb25, unwind: bb37];
    }

    bb25: {
        _58 = move (_59.0: u8);
        switchInt(move _58) -> [227: bb26, otherwise: bb35];
    }

    bb26: {
        _61 = CheckedSub(_38, _39);
        assert(!move (_61.1: bool), "attempt to compute `{} - {}`, which would overflow", _38, _39) -> [success: bb27, unwind: bb37];
    }

    bb27: {
        _60 = move (_61.0: u8);
        switchInt(move _60) -> [11: bb28, otherwise: bb35];
    }

    bb28: {
        _63 = _39 as u16 (IntToInt);
        _64 = _40 as u16 (IntToInt);
        _65 = CheckedMul(_63, _64);
        assert(!move (_65.1: bool), "attempt to compute `{} * {}`, which would overflow", move _63, move _64) -> [success: bb29, unwind: bb37];
    }

    bb29: {
        _62 = move (_65.0: u16);
        switchInt(move _62) -> [11100: bb30, otherwise: bb35];
    }

    bb30: {
        _67 = CheckedSub(_37, _40);
        assert(!move (_67.1: bool), "attempt to compute `{} - {}`, which would overflow", _37, _40) -> [success: bb31, unwind: bb37];
    }

    bb31: {
        _66 = move (_67.0: u8);
        switchInt(move _66) -> [5: bb32, otherwise: bb35];
    }

    bb32: {
        _71 = const _;
        _70 = _71 as &[&str] (PointerCoercion(Unsize));
        _69 = std::fmt::Arguments::<'_>::new_const(move _70) -> [return: bb33, unwind: bb37];
    }

    bb33: {
        _68 = std::io::_print(move _69) -> [return: bb39, unwind: bb37];
    }

    bb34: {
        drop(_2) -> [return: bb36, unwind continue];
    }

    bb35: {
        drop(_2) -> [return: bb36, unwind continue];
    }

    bb36: {
        return;
    }

    bb37 (cleanup): {
        drop(_2) -> [return: bb38, unwind terminate(cleanup)];
    }

    bb38 (cleanup): {
        resume;
    }

    bb39: {
        goto -> bb34;
    }
}
```
It's not too difficult to find the rough structure of this code. The tricky part was to lay out the scope, order of operations and control flow to make the various scopes and basic block orderings match precisely. As this was a several hour process of tedious debugging, I'll just show the final result:

```rs
use std::ops::Deref;

fn main() {
    let reader = std::io::stdin();
    let mut buf = std::string::String::new();
    let _ = reader.read_line(&mut buf).expect("read failed");

    {
        let flag = buf.deref().trim().as_bytes();
        if flag.len() == 10 {
            if flag[0] == 102 &&
                flag[1] == 108 &&
                flag[2] == 97 &&
                flag[3] == 103 &&
                flag[4] == 123 &&
                flag[9] == 125
            {
                let (a, b, c, d) = (flag[5], flag[6], flag[7], flag[8]);
                if a + b == 227 && b - c == 11 && (c as u16 * d as u16) == 11100 && a - d == 5 {
                    println!("yes");
                } else {
	                return;
	            }
            } else {
                return;
            }
        }
    }
}
```
This gives us the second part of the flag.

# 3 (Print LIR)
Finally, we can solve the third part. Like part 1, we iterate over items and compare their tag. This time, we check if the kind is `0x4` - a function item.
We run some query and then run `<rustc_middle::middle::codegen_fn_attrs::CodegenFnAttrFlags as core::cmp::PartialEq>::eq::h6c2c8268654a4f2c` on a field in the result and a constant item. Looking up this [type](https://doc.rust-lang.org/beta/nightly-rustc/rustc_middle/middle/codegen_fn_attrs/struct.CodegenFnAttrFlags.html), we can see it's simply a bitfield for flags. It's compared against the value `0x200`, which corresponds to `#[used]`. We can assume the struct it's attached to is a [`CodegenFnAttrs`](https://doc.rust-lang.org/beta/nightly-rustc/rustc_middle/middle/codegen_fn_attrs/struct.CodegenFnAttrs.html).

```c
            if ((<rustc_middle::middle:...::PartialEq>::eq::h6c2c8268654a4f2c(&func_thing->field_30, &data_119438[8]) & 1) != 0) {
                int32_t symbol = core::option::Option<T>::unwrap::h070ee3e5d6b6117c(func_thing->option_symbol)
                ptr, len = _RNvMs8_NtCsPV1sGaye2_10rustc_span6symbolNtB5_6Symbol6as_str(&symbol)
                struct str_slice str
                str.len = len
                str.ptr = ptr

```
We then `unwrap` some `Option` field on the struct containing a `Symbol`. (`Symbol`s are interned strings in the Rust compiler, represented as incremental 32-bit integers used to index into a global string table.)
The string value of this symbol is compared against `gimmeflag`. We can therefore assume that this code is checking that *some* codegen attribute on this function is `gimmeflag`. Going through each, we can eventually find that `#[link_name = "gimmeflag"]` gives us our final flag portion.

# Conclusion
Putting it all together, the final solution we send to the server to get the flag is
```rs
struct Solution(     (                  ),         ( ),           ( ),        ( ),            ( ),       ( ),           ( ),      (                  ),     ( ),    ( ),   ( ),  (      ),);
use std::ops::Deref;

fn main() {
    let reader = std::io::stdin();
    let mut buf = std::string::String::new();
    let _ = reader.read_line(&mut buf).expect("read failed");

    {
        let flag = buf.deref().trim().as_bytes();
        if flag.len() == 10 {
            if flag[0] == 102 &&
                flag[1] == 108 &&
                flag[2] == 97 &&
                flag[3] == 103 &&
                flag[4] == 123 &&
                flag[9] == 125
            {
                let (a, b, c, d) = (flag[5], flag[6], flag[7], flag[8]);
                if a + b == 227 && b - c == 11 && (c as u16 * d as u16) == 11100 && a - d == 5 {
                    println!("yes");
                } else { return; }
            } else{
                return;
            }
        }
    }
}
#[used]
#[link_name = "gimmeflag"]
pub fn gimmeflag() {}
```

This was a really interesting challenge, thanks to the author for creating it.
