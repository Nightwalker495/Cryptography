#ifndef CRYPTOGRAPHICTOOLS_INPUTPARSER_H
#define CRYPTOGRAPHICTOOLS_INPUTPARSER_H

#include <vector>
#include <iostream>

namespace cryptotools
{
template <typename T>
class InputParser
{
public:
    using items_list_t = std::vector<T>;
    using iterator = items_list_t::iterator;
    using const_iterator = items_list_t::const_iterator;
    
    InputParser(std::istream* stream)
    {
        ProcessEntireInput();
    }
    
    iterator begin()
    {
        return items_.begin();
    }
    
    iterator end()
    {
        return items_.end();
    }
    
    const_iterator cbegin() const
    {
        return items_.cbegin();
    }
    
    const_iterator cend() const
    {
        return items_.cend();
    }
    
private:
    void ProcessEntireInput()
    {
    
    }
    
    std::istream* in_stream_;
    items_list_t items_;
};
}

#endif //CRYPTOGRAPHICTOOLS_INPUTPARSER_H
