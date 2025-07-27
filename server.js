// Ordinal Marketplace Backend
// Node.js + Express + SQLite + Bitcoin Integration

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

// Bitcoin libraries
const bitcoin = require('bitcoinjs-lib');
const ecc = require('tiny-secp256k1');
const { BIP32Factory } = require('bip32');
const bip39 = require('bip39');

// Initialize BIP32 with secp256k1
const bip32 = BIP32Factory(ecc);
bitcoin.initEccLib(ecc);

const app = express();
const PORT = process.env.PORT || 3000;

// Bitcoin network (testnet for development, mainnet for production)
const NETWORK = bitcoin.networks.testnet; // Change to bitcoin.networks.bitcoin for mainnet

// Site's master key for escrow (in production, use secure key management)
const SITE_MASTER_SEED = process.env.SITE_MASTER_SEED || 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const siteMasterKey = bip32.fromSeed(bip39.mnemonicToSeedSync(SITE_MASTER_SEED), NETWORK);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Database connection
let db;

// Initialize database
async function initializeDatabase() {
    try {
        db = await open({
            filename: './marketplace.db',
            driver: sqlite3.Database
        });

        console.log('Connected to SQLite database');
        await createTables();
        await seedInitialData();
    } catch (error) {
        console.error('Database initialization error:', error);
    }
}

// Create database tables
async function createTables() {
    // Sellers table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS sellers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(50) UNIQUE NOT NULL,
            avatar VARCHAR(10) NOT NULL,
            rating DECIMAL(2,1) DEFAULT 0.0,
            total_sales INTEGER DEFAULT 0,
            verified BOOLEAN DEFAULT FALSE,
            demo_private_key VARCHAR(64),
            demo_public_key VARCHAR(66),
            demo_address VARCHAR(100),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Ordinal listings table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS ordinal_listings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            inscription_id VARCHAR(100) UNIQUE NOT NULL,
            inscription_number INTEGER NOT NULL,
            seller_id INTEGER NOT NULL,
            target_timestamp DATETIME NOT NULL,
            actual_timestamp DATETIME NOT NULL,
            time_difference_seconds INTEGER NOT NULL,
            block_height INTEGER NOT NULL,
            block_hash VARCHAR(64) NOT NULL,
            price_btc DECIMAL(10,8) NOT NULL,
            price_usd INTEGER,
            content_type VARCHAR(50) DEFAULT 'text/plain',
            content_preview VARCHAR(10) NOT NULL,
            description TEXT,
            tags JSON,
            status VARCHAR(20) DEFAULT 'active',
            exact_match BOOLEAN DEFAULT FALSE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (seller_id) REFERENCES sellers (id)
        )
    `);

    // Multisig transactions table (for escrow)
    await db.exec(`
        CREATE TABLE IF NOT EXISTS multisig_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            listing_id INTEGER NOT NULL,
            buyer_pubkey VARCHAR(66),
            seller_pubkey VARCHAR(66),
            site_pubkey VARCHAR(66),
            buyer_address VARCHAR(100),
            seller_address VARCHAR(100),
            multisig_address VARCHAR(100),
            multisig_script_hex TEXT,
            redeem_script_hex TEXT,
            psbt_hex TEXT,
            transaction_status VARCHAR(20) DEFAULT 'pending',
            buyer_signed BOOLEAN DEFAULT FALSE,
            seller_signed BOOLEAN DEFAULT FALSE,
            escrow_signed BOOLEAN DEFAULT FALSE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at DATETIME,
            FOREIGN KEY (listing_id) REFERENCES ordinal_listings (id)
        )
    `);

    // Search history table (for analytics)
    await db.exec(`
        CREATE TABLE IF NOT EXISTS search_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_date DATE NOT NULL,
            target_time TIME NOT NULL,
            target_timestamp DATETIME NOT NULL,
            results_found INTEGER DEFAULT 0,
            user_ip VARCHAR(45),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    console.log('Database tables created successfully');
}

// Seed initial data
async function seedInitialData() {
    try {
        // Check if data already exists
        const existingSellers = await db.get('SELECT COUNT(*) as count FROM sellers');
        if (existingSellers.count > 0) {
            console.log('Database already seeded');
            return;
        }

        // Generate demo keys for sellers
        function generateDemoKeyForSeller(sellerName) {
            const seed = crypto.createHash('sha256').update(`demo_seller_${sellerName}`).digest();
            const keyPair = bip32.fromPrivateKey(seed, Buffer.alloc(32), NETWORK);
            return {
                privateKey: keyPair.privateKey.toString('hex'),
                publicKey: keyPair.publicKey.toString('hex'),
                address: bitcoin.payments.p2wpkh({ 
                    pubkey: keyPair.publicKey, 
                    network: NETWORK 
                }).address
            };
        }

        // Insert sellers for 02/22/2022 listings with demo keys
        const sellers = [
            {
                username: 'PrecisionTimer',
                avatar: 'PT',
                rating: 4.8,
                total_sales: 156,
                verified: true,
                ...generateDemoKeyForSeller('PrecisionTimer')
            },
            {
                username: 'ChronoCollector',
                avatar: 'CC', 
                rating: 4.6,
                total_sales: 89,
                verified: true,
                ...generateDemoKeyForSeller('ChronoCollector')
            },
            {
                username: 'TimeVault_BTC',
                avatar: 'TV',
                rating: 4.4,
                total_sales: 34,
                verified: false,
                ...generateDemoKeyForSeller('TimeVault_BTC')
            }
        ];

        // Insert sellers
        for (const seller of sellers) {
            await db.run(`
                INSERT INTO sellers (username, avatar, rating, total_sales, verified, demo_private_key, demo_public_key, demo_address)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `, [seller.username, seller.avatar, seller.rating, seller.total_sales, seller.verified, seller.privateKey, seller.publicKey, seller.address]);
        }

        // Target date/time: 02/22/2022 at 12:00:00 PM UTC
        const targetTimestamp = '2022-02-22 12:00:00';
        
        // Create 3 listings for this specific timestamp
        const listings = [
            {
                seller_id: 1,
                inscription_id: generateInscriptionId(),
                inscription_number: generateInscriptionNumber(),
                actual_timestamp: '2022-02-22 12:00:00', // Exact match
                time_difference_seconds: 0,
                block_height: 724000,
                price_btc: 0.01,
                content_preview: '🎯',
                description: 'Perfect timestamp match for 2/22/22',
                exact_match: true,
                tags: JSON.stringify(['exact_match', 'twos_day', 'palindrome'])
            },
            {
                seller_id: 2,
                inscription_id: generateInscriptionId(),
                inscription_number: generateInscriptionNumber(),
                actual_timestamp: '2022-02-22 12:02:30', // 2.5 minutes after
                time_difference_seconds: 150,
                block_height: 724001,
                price_btc: 0.015,
                content_preview: '⭐',
                description: 'Close match to your special moment',
                exact_match: false,
                tags: JSON.stringify(['close_match', 'twos_day', 'premium'])
            },
            {
                seller_id: 3,
                inscription_id: generateInscriptionId(),
                inscription_number: generateInscriptionNumber(),
                actual_timestamp: '2022-02-22 11:58:15', // 1.75 minutes before
                time_difference_seconds: 105,
                block_height: 723999,
                price_btc: 0.02,
                content_preview: '💎',
                description: 'Rare pre-moment inscription',
                exact_match: false,
                tags: JSON.stringify(['pre_moment', 'twos_day', 'rare'])
            }
        ];

        // Insert listings
        for (const listing of listings) {
            await db.run(`
                INSERT INTO ordinal_listings (
                    seller_id, inscription_id, inscription_number, target_timestamp,
                    actual_timestamp, time_difference_seconds, block_height, block_hash,
                    price_btc, price_usd, content_preview, description, exact_match, tags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `, [
                listing.seller_id,
                listing.inscription_id,
                listing.inscription_number,
                targetTimestamp,
                listing.actual_timestamp,
                listing.time_difference_seconds,
                listing.block_height,
                generateBlockHash(),
                listing.price_btc,
                calculateUSDPrice(listing.price_btc),
                listing.content_preview,
                listing.description,
                listing.exact_match,
                listing.tags
            ]);
        }

        console.log('Database seeded with 3 listings for 02/22/2022 12:00:00 UTC');

    } catch (error) {
        console.error('Error seeding database:', error);
    }
}

// Helper functions
function generateInscriptionId() {
    return crypto.randomBytes(32).toString('hex') + 'i0';
}

function generateInscriptionNumber() {
    return Math.floor(Math.random() * 10000000) + 1000000;
}

function generateBlockHash() {
    return '00000000000000000' + crypto.randomBytes(23).toString('hex');
}

function calculateUSDPrice(btcPrice, btcUsdRate = 38000) {
    // Using approximate BTC price for Feb 2022
    return Math.round(btcPrice * btcUsdRate);
}

// Bitcoin utility functions
function generateSiteKeyPair(index = 0) {
    // Derive a unique key pair for each transaction
    const derivedKey = siteMasterKey.derive(0).derive(index);
    return {
        privateKey: derivedKey.privateKey,
        publicKey: derivedKey.publicKey,
        address: bitcoin.payments.p2wpkh({ 
            pubkey: derivedKey.publicKey, 
            network: NETWORK 
        }).address
    };
}

function createMultisigAddress(buyerPubkey, sellerPubkey, sitePubkey) {
    try {
        // Convert hex strings to buffers if needed
        const buyerPubkeyBuffer = Buffer.isBuffer(buyerPubkey) ? buyerPubkey : Buffer.from(buyerPubkey, 'hex');
        const sellerPubkeyBuffer = Buffer.isBuffer(sellerPubkey) ? sellerPubkey : Buffer.from(sellerPubkey, 'hex');
        const sitePubkeyBuffer = Buffer.isBuffer(sitePubkey) ? sitePubkey : Buffer.from(sitePubkey, 'hex');

        // Sort pubkeys for deterministic multisig
        const sortedPubkeys = [buyerPubkeyBuffer, sellerPubkeyBuffer, sitePubkeyBuffer].sort(Buffer.compare);

        // Create 2-of-3 multisig redeem script
        const redeemScript = bitcoin.script.compile([
            bitcoin.opcodes.OP_2,
            ...sortedPubkeys,
            bitcoin.opcodes.OP_3,
            bitcoin.opcodes.OP_CHECKMULTISIG
        ]);

        // Create P2WSH (Wrapped SegWit) address
        const p2wsh = bitcoin.payments.p2wsh({
            redeem: { output: redeemScript },
            network: NETWORK
        });

        // Also create P2SH-wrapped version for broader compatibility
        const p2sh = bitcoin.payments.p2sh({
            redeem: p2wsh,
            network: NETWORK
        });

        return {
            address: p2sh.address, // P2SH-wrapped P2WSH for compatibility
            redeemScript: redeemScript.toString('hex'),
            scriptHex: p2sh.output.toString('hex'),
            witnessScript: redeemScript.toString('hex'),
            sortedPubkeys: sortedPubkeys.map(pk => pk.toString('hex'))
        };
    } catch (error) {
        console.error('Error creating multisig address:', error);
        throw new Error('Failed to create multisig address');
    }
}

function validatePubkey(pubkeyHex) {
    try {
        if (!pubkeyHex || typeof pubkeyHex !== 'string') {
            return false;
        }
        
        // Remove any whitespace
        pubkeyHex = pubkeyHex.trim();
        
        // Check length (33 bytes = 66 hex chars for compressed, 65 bytes = 130 hex chars for uncompressed)
        if (pubkeyHex.length !== 66 && pubkeyHex.length !== 130) {
            return false;
        }
        
        // Check if it's valid hex
        if (!/^[0-9a-fA-F]+$/.test(pubkeyHex)) {
            return false;
        }
        
        const pubkeyBuffer = Buffer.from(pubkeyHex, 'hex');
        
        // Validate with secp256k1
        return ecc.isPoint(pubkeyBuffer);
    } catch (error) {
        return false;
    }
}

// API Routes

// Search for ordinals by target timestamp
app.post('/api/search', async (req, res) => {
    try {
        const { target_date, target_time, time_range_minutes = 60 } = req.body;
        
        if (!target_date || !target_time) {
            return res.status(400).json({ 
                error: 'target_date and target_time are required' 
            });
        }

        const targetTimestamp = `${target_date} ${target_time}`;
        const timeRangeSeconds = time_range_minutes * 60;

        // Log search for analytics
        await db.run(`
            INSERT INTO search_history (target_date, target_time, target_timestamp, user_ip)
            VALUES (?, ?, ?, ?)
        `, [target_date, target_time, targetTimestamp, req.ip]);

        // Search for listings within time range
        const listings = await db.all(`
            SELECT 
                ol.*,
                s.username as seller_name,
                s.avatar as seller_avatar,
                s.rating as seller_rating,
                s.total_sales as seller_sales,
                s.verified as seller_verified
            FROM ordinal_listings ol
            JOIN sellers s ON ol.seller_id = s.id
            WHERE ol.target_timestamp = ?
            AND ol.status = 'active'
            AND ol.time_difference_seconds <= ?
            ORDER BY ol.time_difference_seconds ASC, ol.price_btc ASC
        `, [targetTimestamp, timeRangeSeconds]);

        // Update search history with results count
        await db.run(`
            UPDATE search_history 
            SET results_found = ?
            WHERE id = (
                SELECT id FROM search_history 
                WHERE target_timestamp = ? AND user_ip = ?
                ORDER BY created_at DESC
                LIMIT 1
            )
        `, [listings.length, targetTimestamp, req.ip]);

        // Format response
        const formattedListings = listings.map(listing => ({
            id: listing.id,
            inscription_id: listing.inscription_id,
            inscription_number: listing.inscription_number,
            timestamp: listing.actual_timestamp,
            block_height: listing.block_height,
            block_hash: listing.block_hash,
            price: listing.price_btc,
            price_usd: listing.price_usd,
            content: listing.content_preview,
            description: listing.description,
            exact_match: Boolean(listing.exact_match),
            time_diff: listing.time_difference_seconds,
            tags: JSON.parse(listing.tags || '[]'),
            seller: {
                name: listing.seller_name,
                avatar: listing.seller_avatar,
                rating: listing.seller_rating,
                sales: listing.seller_sales,
                verified: Boolean(listing.seller_verified)
            }
        }));

        res.json({
            success: true,
            target_timestamp: targetTimestamp,
            results_found: listings.length,
            listings: formattedListings
        });

    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ 
            error: 'Internal server error during search' 
        });
    }
});

// Get specific listing details
app.get('/api/listing/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const listing = await db.get(`
            SELECT 
                ol.*,
                s.username as seller_name,
                s.avatar as seller_avatar,
                s.rating as seller_rating,
                s.total_sales as seller_sales,
                s.verified as seller_verified
            FROM ordinal_listings ol
            JOIN sellers s ON ol.seller_id = s.id
            WHERE ol.id = ?
        `, [id]);

        if (!listing) {
            return res.status(404).json({ error: 'Listing not found' });
        }

        const formattedListing = {
            id: listing.id,
            inscription_id: listing.inscription_id,
            inscription_number: listing.inscription_number,
            timestamp: listing.actual_timestamp,
            target_timestamp: listing.target_timestamp,
            block_height: listing.block_height,
            block_hash: listing.block_hash,
            price: listing.price_btc,
            price_usd: listing.price_usd,
            content: listing.content_preview,
            content_type: listing.content_type,
            description: listing.description,
            exact_match: Boolean(listing.exact_match),
            time_diff: listing.time_difference_seconds,
            tags: JSON.parse(listing.tags || '[]'),
            status: listing.status,
            seller: {
                name: listing.seller_name,
                avatar: listing.seller_avatar,
                rating: listing.seller_rating,
                sales: listing.seller_sales,
                verified: Boolean(listing.seller_verified)
            },
            created_at: listing.created_at
        };

        res.json({
            success: true,
            listing: formattedListing
        });

    } catch (error) {
        console.error('Get listing error:', error);
        res.status(500).json({ 
            error: 'Internal server error' 
        });
    }
});

// Initiate purchase (create multisig transaction)
app.post('/api/purchase/initiate', async (req, res) => {
    try {
        const { listing_id, buyer_pubkey } = req.body;

        if (!listing_id) {
            return res.status(400).json({ 
                error: 'listing_id is required' 
            });
        }

        if (!buyer_pubkey) {
            return res.status(400).json({ 
                error: 'buyer_pubkey is required' 
            });
        }

        // Validate buyer public key
        if (!validatePubkey(buyer_pubkey)) {
            return res.status(400).json({ 
                error: 'Invalid buyer public key format' 
            });
        }

        // Check if listing exists and get seller's demo key
        const listing = await db.get(`
            SELECT ol.*, s.username as seller_name, s.demo_public_key as seller_pubkey, s.demo_address as seller_address
            FROM ordinal_listings ol
            JOIN sellers s ON ol.seller_id = s.id
            WHERE ol.id = ? AND ol.status = 'active'
        `, [listing_id]);

        if (!listing) {
            return res.status(404).json({ error: 'Listing not found or unavailable' });
        }

        if (!listing.seller_pubkey) {
            return res.status(500).json({ error: 'Seller demo key not found' });
        }

        // Generate site's key pair for this transaction
        const siteKeyPair = generateSiteKeyPair(listing_id);
        const sitePubkey = siteKeyPair.publicKey.toString('hex');

        // Create 2-of-3 multisig address using buyer, seller (from DB), and site keys
        const multisigInfo = createMultisigAddress(
            buyer_pubkey,
            listing.seller_pubkey,
            sitePubkey
        );

        // Create multisig transaction record
        const multisigTx = await db.run(`
            INSERT INTO multisig_transactions (
                listing_id, buyer_pubkey, seller_pubkey, site_pubkey,
                multisig_address, multisig_script_hex, redeem_script_hex, transaction_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            listing_id,
            buyer_pubkey,
            listing.seller_pubkey,
            sitePubkey,
            multisigInfo.address,
            multisigInfo.scriptHex,
            multisigInfo.redeemScript,
            'multisig_created'
        ]);

        // Update listing status
        await db.run(`
            UPDATE ordinal_listings SET status = 'pending_purchase' WHERE id = ?
        `, [listing_id]);

        res.json({
            success: true,
            transaction_id: multisigTx.lastID,
            multisig_address: multisigInfo.address,
            buyer_pubkey: buyer_pubkey,
            seller_pubkey: listing.seller_pubkey,
            seller_address: listing.seller_address,
            site_pubkey: sitePubkey,
            redeem_script: multisigInfo.redeemScript,
            sorted_pubkeys: multisigInfo.sortedPubkeys,
            amount_btc: listing.price_btc,
            amount_sats: Math.round(listing.price_btc * 100000000),
            message: '2-of-3 multisig address created successfully',
            demo_info: {
                buyer_key: buyer_pubkey,
                seller_key: listing.seller_pubkey,
                seller_name: listing.seller_name,
                site_key: sitePubkey,
                multisig_type: '2-of-3'
            },
            next_steps: [
                'Send payment to the multisig address',
                'Seller will transfer the ordinal',
                'Funds will be released upon confirmation'
            ],
            instructions: {
                payment: `Send exactly ${listing.price_btc} BTC to: ${multisigInfo.address}`,
                security: 'Funds are secured by 2-of-3 multisig escrow',
                release: 'Payment will be released when 2 of 3 parties sign'
            }
        });

    } catch (error) {
        console.error('Purchase initiation error:', error);
        res.status(500).json({ 
            error: 'Internal server error during purchase initiation',
            details: error.message 
        });
    }
});

// Get multisig transaction details
app.get('/api/multisig/:transaction_id', async (req, res) => {
    try {
        const { transaction_id } = req.params;

        const multisigTx = await db.get(`
            SELECT 
                mt.*,
                ol.price_btc,
                ol.inscription_id,
                s.username as seller_name
            FROM multisig_transactions mt
            JOIN ordinal_listings ol ON mt.listing_id = ol.id
            JOIN sellers s ON ol.seller_id = s.id
            WHERE mt.id = ?
        `, [transaction_id]);

        if (!multisigTx) {
            return res.status(404).json({ error: 'Multisig transaction not found' });
        }

        res.json({
            success: true,
            transaction: {
                id: multisigTx.id,
                listing_id: multisigTx.listing_id,
                multisig_address: multisigTx.multisig_address,
                amount_btc: multisigTx.price_btc,
                amount_sats: Math.round(multisigTx.price_btc * 100000000),
                status: multisigTx.transaction_status,
                buyer_signed: Boolean(multisigTx.buyer_signed),
                seller_signed: Boolean(multisigTx.seller_signed),
                escrow_signed: Boolean(multisigTx.escrow_signed),
                created_at: multisigTx.created_at,
                inscription_id: multisigTx.inscription_id,
                seller_name: multisigTx.seller_name,
                pubkeys: {
                    buyer: multisigTx.buyer_pubkey,
                    seller: multisigTx.seller_pubkey,
                    site: multisigTx.site_pubkey
                }
            }
        });

    } catch (error) {
        console.error('Get multisig transaction error:', error);
        res.status(500).json({ 
            error: 'Internal server error' 
        });
    }
});

// Generate a demo key pair for testing
app.post('/api/generate-demo-keypair', (req, res) => {
    try {
        // Generate a random private key for demo purposes
        const privateKey = crypto.randomBytes(32);
        
        // Create key pair using BIP32 (which we already have initialized)
        const keyPair = bip32.fromPrivateKey(privateKey, Buffer.alloc(32), NETWORK);
        
        const publicKey = keyPair.publicKey.toString('hex');
        const address = bitcoin.payments.p2wpkh({ 
            pubkey: keyPair.publicKey, 
            network: NETWORK 
        }).address;

        res.json({
            success: true,
            demo_keypair: {
                private_key: keyPair.privateKey.toString('hex'),
                public_key: publicKey,
                address: address,
                network: NETWORK === bitcoin.networks.testnet ? 'testnet' : 'mainnet',
                warning: 'This is for demo purposes only. Never use these keys with real funds!'
            }
        });
    } catch (error) {
        console.error('Generate demo keypair error:', error);
        res.status(500).json({ 
            error: 'Failed to generate demo keypair',
            details: error.message 
        });
    }
});

// Validate a public key
app.post('/api/validate-pubkey', (req, res) => {
    try {
        const { pubkey } = req.body;
        
        if (!pubkey) {
            return res.status(400).json({ 
                error: 'pubkey is required' 
            });
        }

        const isValid = validatePubkey(pubkey);
        
        if (isValid) {
            // Also return the corresponding address for verification
            const pubkeyBuffer = Buffer.from(pubkey, 'hex');
            const address = bitcoin.payments.p2wpkh({ 
                pubkey: pubkeyBuffer, 
                network: NETWORK 
            }).address;

            res.json({
                success: true,
                valid: true,
                pubkey: pubkey,
                address: address,
                compressed: pubkey.length === 66,
                network: NETWORK === bitcoin.networks.testnet ? 'testnet' : 'mainnet'
            });
        } else {
            res.json({
                success: true,
                valid: false,
                error: 'Invalid public key format or value'
            });
        }
    } catch (error) {
        console.error('Validate pubkey error:', error);
        res.status(500).json({ 
            error: 'Failed to validate public key' 
        });
    }
});

// Get marketplace statistics
app.get('/api/stats', async (req, res) => {
    try {
        const stats = await db.get(`
            SELECT 
                COUNT(*) as total_listings,
                COUNT(CASE WHEN status = 'active' THEN 1 END) as active_listings,
                COUNT(CASE WHEN exact_match = 1 THEN 1 END) as exact_matches,
                AVG(price_btc) as avg_price_btc,
                MIN(price_btc) as min_price_btc,
                MAX(price_btc) as max_price_btc
            FROM ordinal_listings
        `);

        const searchStats = await db.get(`
            SELECT 
                COUNT(*) as total_searches,
                COUNT(CASE WHEN results_found > 0 THEN 1 END) as successful_searches,
                AVG(results_found) as avg_results_per_search
            FROM search_history
            WHERE created_at >= datetime('now', '-30 days')
        `);

        res.json({
            success: true,
            stats: {
                listings: stats,
                searches: searchStats,
                last_updated: new Date().toISOString()
            }
        });

    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ 
            error: 'Internal server error' 
        });
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ 
        error: 'Internal server error' 
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ 
        error: 'Endpoint not found' 
    });
});

// Start server
async function startServer() {
    await initializeDatabase();
    
    app.listen(PORT, () => {
        console.log(`🚀 Ordinal Marketplace Backend running on port ${PORT}`);
        console.log(`📊 Database: marketplace.db`);
        console.log(`🔍 API Docs: http://localhost:${PORT}/api/`);
        console.log(`💎 Test search: 2022-02-22 12:00:00`);
        console.log(`🔗 Network: ${NETWORK === bitcoin.networks.testnet ? 'Bitcoin Testnet' : 'Bitcoin Mainnet'}`);
    });
}

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n🛑 Shutting down gracefully...');
    if (db) {
        await db.close();
        console.log('📦 Database connection closed');
    }
    process.exit(0);
});

startServer().catch(console.error);

module.exports = app;
