import unittest
from merkle_proof import *
from merkle_tree import *


class TestMerkleProof(unittest.TestCase):

    def test_one_proof(self):
        """Test that the proof can handle a tree with only one transaction.
        No other data is necessary to arrive at the block header
        """
        tx1 = 'a'

        merkle_tree = MerkleTree([tx1])

        self.assertEqual([], merkle_proof(tx1, merkle_tree))

    def test_small_proof(self):
        """Test that the proof can handle a tree with only two transactions"""
        tx1 = 'a'
        tx2 = 'b'

        merkle_tree = MerkleTree([tx1, tx2])

        self.assertEqual([tx2], merkle_proof(tx1, merkle_tree))
        self.assertEqual([tx1], merkle_proof(tx2, merkle_tree))

    def test_medium_proof(self):
        """Test that the proof can handle a tree with up to four
        transactions
        """
        tx1 = 'a'
        tx2 = 'b'
        tx3 = 'c'
        tx4 = 'd'

        merkle_tree = MerkleTree([tx1, tx2, tx3, tx4])

        data = tx1 + tx2
        data = hash_data(data, 'sha256')

        self.assertEqual([data, tx3], merkle_proof(tx4, merkle_tree))
        self.assertEqual([data, tx4], merkle_proof(tx3, merkle_tree))

        data = tx3 + tx4
        data = hash_data(data, 'sha256')

        self.assertEqual([data, tx1], merkle_proof(tx2, merkle_tree))
        self.assertEqual([data, tx2], merkle_proof(tx1, merkle_tree))

    def test_large_proof(self):
        """Test that the proof can handle a tree with up to eight
        transaction"""
        tx1 = 'a'
        tx2 = 'b'
        tx3 = 'c'
        tx4 = 'd'
        tx5 = 'e'
        tx6 = 'f'
        tx7 = 'g'
        tx8 = 'h'

        data1 = tx1 + tx2
        data1 = hash_data(data1, 'sha256')
        data2 = tx5 + tx6
        data2 = hash_data(data2, 'sha256')
        data3 = tx7 + tx8
        data3 = hash_data(data3, 'sha256')
        data4 = data2 + data3
        data4 = hash_data(data4, 'sha256')

        merkle_tree = MerkleTree([tx1, tx2, tx3, tx4, tx5, tx6, tx7, tx8])

        self.assertEqual([data4, data1, tx4], merkle_proof(tx3, merkle_tree))

    def test_verify_proof(self):
        """Test that the proof can be verified; the hash must be reconstructed
        exactly right. Issues may come up with the order in which data is
        hashed
        """
        tx1 = 'a'
        tx2 = 'b'
        tx3 = 'c'
        tx4 = 'd'

        merkle_tree = MerkleTree([tx1, tx2, tx3, tx4])
        proof = merkle_proof(tx1, merkle_tree)
        verified_hash = verify_proof(tx1, proof)

        self.assertEqual(verified_hash, merkle_tree.block_header)

if __name__ == '__main__':
    unittest.main()
