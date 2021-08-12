//===----------------------------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is dual licensed under the MIT and the University of Illinois Open
// Source Licenses. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

// XFAIL: libcpp-no-exceptions
// <optional>

// template <class U, class... Args>
//     constexpr
//     explicit optional(in_place_t, initializer_list<U> il, Args&&... args);

#include <experimental/optional>
#include <type_traits>
#include <vector>
#include <cassert>

#if _LIBCPP_STD_VER > 11

using std::experimental::optional;
using std::experimental::in_place_t;
using std::experimental::in_place;

class X
{
    int i_;
    int j_ = 0;
public:
    X() : i_(0) {}
    X(int i) : i_(i) {}
    X(int i, int j) : i_(i), j_(j) {}

    ~X() {}

    friend bool operator==(const X& x, const X& y)
        {return x.i_ == y.i_ && x.j_ == y.j_;}
};

class Y
{
    int i_;
    int j_ = 0;
public:
    constexpr Y() : i_(0) {}
    constexpr Y(int i) : i_(i) {}
    constexpr Y(std::initializer_list<int> il) : i_(il.begin()[0]), j_(il.begin()[1]) {}

    friend constexpr bool operator==(const Y& x, const Y& y)
        {return x.i_ == y.i_ && x.j_ == y.j_;}
};

class Z
{
    int i_;
    int j_ = 0;
public:
    constexpr Z() : i_(0) {}
    constexpr Z(int i) : i_(i) {}
    constexpr Z(std::initializer_list<int> il) : i_(il.begin()[0]), j_(il.begin()[1])
        {throw 6;}

    friend constexpr bool operator==(const Z& x, const Z& y)
        {return x.i_ == y.i_ && x.j_ == y.j_;}
};


#endif  // _LIBCPP_STD_VER > 11

int main()
{
#if _LIBCPP_STD_VER > 11
    {
        static_assert(!std::is_constructible<X, std::initializer_list<int>&>::value, "");
        static_assert(!std::is_constructible<optional<X>, std::initializer_list<int>&>::value, "");
    }
    {
        optional<std::vector<int>> opt(in_place, {3, 1});
        assert(static_cast<bool>(opt) == true);
        assert((*opt == std::vector<int>{3, 1}));
        assert(opt->size() == 2);
    }
    {
        optional<std::vector<int>> opt(in_place, {3, 1}, std::allocator<int>());
        assert(static_cast<bool>(opt) == true);
        assert((*opt == std::vector<int>{3, 1}));
        assert(opt->size() == 2);
    }
    {
        static_assert(std::is_constructible<optional<Y>, std::initializer_list<int>&>::value, "");
        constexpr optional<Y> opt(in_place, {3, 1});
        static_assert(static_cast<bool>(opt) == true, "");
        static_assert(*opt == Y{3, 1}, "");

        struct test_constexpr_ctor
            : public optional<Y>
        {
            constexpr test_constexpr_ctor(in_place_t, std::initializer_list<int> i) 
                : optional<Y>(in_place, i) {}
        };

    }
    {
        static_assert(std::is_constructible<optional<Z>, std::initializer_list<int>&>::value, "");
        try
        {
            optional<Z> opt(in_place, {3, 1});
            assert(false);
        }
        catch (int i)
        {
            assert(i == 6);
        }

        struct test_constexpr_ctor
            : public optional<Z>
        {
            constexpr test_constexpr_ctor(in_place_t, std::initializer_list<int> i) 
                : optional<Z>(in_place, i) {}
        };

    }
#endif  // _LIBCPP_STD_VER > 11
}
