#ifndef INDEX_TABLE_HPP
#define INDEX_TABLE_HPP

#include <cstdint>
#include <map>
#include <mutex>
#include <random>

#include "core/peer.hpp"
#include "noise/keypair.hpp"

namespace wg {
class IndexTable {
    /// 提供注册，查找和释放 KeypairIndex 的功能。
   public:
    IndexTable() = default;
    ~IndexTable() = default;

    IndexTable(const IndexTable&) = delete;
    IndexTable& operator=(const IndexTable&) = delete;

    IndexTable(IndexTable&&) = delete;
    IndexTable& operator=(IndexTable&&) = delete;

    Keypair* find_keypair(KeypairIndex idx) const {
        std::lock_guard<std::mutex> lg(mutex_);
        auto it = keypairs_.find(idx);
        return it != keypairs_.end() ? it->second : nullptr;
    }

    bool register_keypair(Keypair* keypair) {
        if (keypair == nullptr) {
            return false;
        }
        std::lock_guard<std::mutex> lg(mutex_);
        KeypairIndex local_index = keypair->local_index;
        if (keypairs_.find(local_index) != keypairs_.end()) {
            return false;
        }
        keypairs_.emplace(local_index, keypair);
        return true;
    }

    Keypair* erase_keypair(KeypairIndex idx) {
        std::lock_guard<std::mutex> lg(mutex_);
        auto it = keypairs_.find(idx);
        if (it == keypairs_.end()) {
            return nullptr;
        }
        Keypair* keypair = it->second;
        keypairs_.erase(it);
        return keypair;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lg(mutex_);
        return keypairs_.size();
    }

    void clear() {
        std::lock_guard<std::mutex> lg(mutex_);
        keypairs_.clear();
    }

   private:
    mutable std::mutex mutex_;
    std::map<KeypairIndex, Keypair*> keypairs_;
};

}  // namespace wg

#endif  // INDEX_TABLE_HPP