(function () {
    const getPathPrefix = () => {
        const path = window.location.pathname;
        if (path.includes('/listings/') || 
            path.includes('/messages/') || 
            path.includes('/profile/') || 
            path.includes('/listing-detail/') || 
            path.includes('/my-listings/') ||
            path.includes('/create-listing/')) {
            return '../';
        }
        return '';
    };

    const mockupUrl = (filename) => `${getPathPrefix()}assets/mockups/${filename}`;

    const svgDataUrl = (label, accent, secondary) =>
        "data:image/svg+xml;utf8," +
        encodeURIComponent(
            `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800">
                <defs>
                    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stop-color="${accent}" />
                        <stop offset="100%" stop-color="${secondary}" />
                    </linearGradient>
                </defs>
                <rect width="1200" height="800" fill="url(#bg)" />
                <circle cx="930" cy="165" r="140" fill="rgba(255,255,255,0.16)" />
                <circle cx="230" cy="640" r="180" fill="rgba(255,255,255,0.12)" />
                <rect x="110" y="118" width="980" height="564" rx="36" fill="rgba(255,255,255,0.14)" stroke="rgba(255,255,255,0.28)" />
                <text x="150" y="270" font-size="64" font-family="Arial, sans-serif" font-weight="700" fill="#ffffff">${label}</text>
                <text x="150" y="350" font-size="30" font-family="Arial, sans-serif" fill="rgba(255,255,255,0.88)">Spear Exchange showcase sample</text>
            </svg>`
        );

    const demoListings = [
        {
            id: 900001,
            user_id: 801,
            seller_name: "Noles Layer Lab",
            seller_email: "showcase+3d1@spearexchange.demo",
            seller_phone: "(850) 555-0131",
            seller_verified: 1,
            seller_created_at: "2025-08-15T12:00:00Z",
            seller: {
                profile_name: "Noles Layer Lab",
                bio: "Generic showcase seller profile for campus spirit-item concepts and small-batch 3D printed decor.",
                is_verified: true,
                member_since: "2025-08-15T12:00:00Z",
                stats: {
                    listings_count: 3,
                    reviews_count: 12,
                    rating: 4.9
                }
            },
            title: "Desk Garnet Helmet Stand",
            description: "Generic showcase listing for a compact desk stand sized for mini helmets, signed footballs, or shelf decor in dorms and apartments.",
            price: 24,
            category: "3d-printed-fsu-items",
            condition: "new",
            listing_type: "goods",
            price_period: "one_time",
            negotiable: false,
            contact_method: "both",
            phone_number: "(850) 555-0131",
            location: "Student Union pickup",
            image_urls: [mockupUrl("helmet_stand.png")],
            created_at: "2026-03-22T14:00:00Z",
            status: "active",
            is_demo: true
        },
        {
            id: 900002,
            user_id: 801,
            seller_name: "Noles Layer Lab",
            seller_email: "showcase+3d2@spearexchange.demo",
            seller_phone: "(850) 555-0131",
            seller_verified: 1,
            seller_created_at: "2025-08-15T12:00:00Z",
            seller: {
                profile_name: "Noles Layer Lab",
                bio: "Generic showcase seller profile for campus spirit-item concepts and small-batch 3D printed decor.",
                is_verified: true,
                member_since: "2025-08-15T12:00:00Z",
                stats: {
                    listings_count: 3,
                    reviews_count: 12,
                    rating: 4.9
                }
            },
            title: "Seminole Keychain Set",
            description: "Showcase concept for a bundle of small spirit-themed keychains that work well as quick campus pickup items and affordable gift ideas.",
            price: 12,
            category: "3d-printed-fsu-items",
            condition: "new",
            listing_type: "goods",
            price_period: "one_time",
            negotiable: true,
            contact_method: "email",
            phone_number: "",
            location: "Dirac Library",
            image_urls: [mockupUrl("keychains.png")],
            created_at: "2026-03-21T11:30:00Z",
            status: "active",
            is_demo: true
        },
        {
            id: 900003,
            user_id: 801,
            seller_name: "Noles Layer Lab",
            seller_email: "showcase+3d3@spearexchange.demo",
            seller_phone: "(850) 555-0131",
            seller_verified: 1,
            seller_created_at: "2025-08-15T12:00:00Z",
            seller: {
                profile_name: "Noles Layer Lab",
                bio: "Generic showcase seller profile for campus spirit-item concepts and small-batch 3D printed decor.",
                is_verified: true,
                member_since: "2025-08-15T12:00:00Z",
                stats: {
                    listings_count: 3,
                    reviews_count: 12,
                    rating: 4.9
                }
            },
            title: "Dorm Shelf Nameplate",
            description: "Generic sample listing for a printed shelf or desk nameplate with room-ready display styling and direct message customization details.",
            price: 18,
            category: "3d-printed-fsu-items",
            condition: "new",
            listing_type: "goods",
            price_period: "one_time",
            negotiable: true,
            contact_method: "both",
            phone_number: "(850) 555-0131",
            location: "Landis Green",
            image_urls: [mockupUrl("nameplate.png")],
            created_at: "2026-03-20T16:45:00Z",
            status: "active",
            is_demo: true
        },
        {
            id: 900101,
            user_id: 901,
            seller_name: "FSU Housing Showcase",
            seller_email: "showcase+sublease1@spearexchange.demo",
            seller_phone: "(850) 555-0146",
            seller_verified: 1,
            seller_created_at: "2025-06-01T09:00:00Z",
            seller: {
                profile_name: "FSU Housing Showcase",
                bio: "Generic showcase housing profile used to preview the sublease flow before live inventory is fully populated.",
                is_verified: true,
                member_since: "2025-06-01T09:00:00Z",
                stats: {
                    listings_count: 3,
                    reviews_count: 7,
                    rating: 4.7
                }
            },
            title: "Furnished 1x1 at Stadium Centre",
            description: "Showcase sublease with a furnished bedroom, walkable access to campus, and a simple monthly-rent layout designed to preview the housing flow.",
            price: 950,
            category: "sublease",
            condition: "n/a",
            listing_type: "sublease",
            price_period: "monthly",
            negotiable: false,
            contact_method: "both",
            phone_number: "(850) 555-0146",
            location: "",
            address_text: "Stadium Centre, Tallahassee",
            housing_type: "apartment",
            bedrooms: 1,
            bathrooms: 1,
            furnished: true,
            utilities_included: true,
            parking_available: true,
            pet_friendly: false,
            roommates_allowed: false,
            lease_transfer_fee: 125,
            availability_start: "2026-05-10",
            availability_end: "2026-07-31",
            sublease_notes: "Summer showcase example with utilities included and direct messaging for timing details.",
            image_urls: [mockupUrl("stadium_centre.png")],
            created_at: "2026-03-24T10:15:00Z",
            status: "active",
            is_demo: true
        },
        {
            id: 900102,
            user_id: 901,
            seller_name: "FSU Housing Showcase",
            seller_email: "showcase+sublease2@spearexchange.demo",
            seller_phone: "(850) 555-0146",
            seller_verified: 1,
            seller_created_at: "2025-06-01T09:00:00Z",
            seller: {
                profile_name: "FSU Housing Showcase",
                bio: "Generic showcase housing profile used to preview the sublease flow before live inventory is fully populated.",
                is_verified: true,
                member_since: "2025-06-01T09:00:00Z",
                stats: {
                    listings_count: 3,
                    reviews_count: 7,
                    rating: 4.7
                }
            },
            title: "Private Room in Collegetown Townhome",
            description: "Generic housing showcase listing with roommate-friendly details, parking, and a monthly rent presentation meant to demonstrate the sublease card and detail view.",
            price: 875,
            category: "sublease",
            condition: "n/a",
            listing_type: "sublease",
            price_period: "monthly",
            negotiable: true,
            contact_method: "email",
            phone_number: "",
            location: "",
            address_text: "Collegetown, Tallahassee",
            housing_type: "townhome",
            bedrooms: 1,
            bathrooms: 1.5,
            furnished: false,
            utilities_included: false,
            parking_available: true,
            pet_friendly: true,
            roommates_allowed: true,
            lease_transfer_fee: 75,
            availability_start: "2026-06-01",
            availability_end: "2026-12-20",
            sublease_notes: "Showcase example for a roommate setup with lease transfer details handled over messages.",
            image_urls: [mockupUrl("collegetown.png")],
            created_at: "2026-03-23T08:50:00Z",
            status: "active",
            is_demo: true
        },
        {
            id: 900103,
            user_id: 902,
            seller_name: "Seminole Leasing Mockups",
            seller_email: "showcase+sublease3@spearexchange.demo",
            seller_phone: "(850) 555-0172",
            seller_verified: 0,
            seller_created_at: "2025-11-10T15:00:00Z",
            seller: {
                profile_name: "Seminole Leasing Mockups",
                bio: "Another generic showcase housing profile to make the browse and seller portfolio views feel populated.",
                is_verified: false,
                member_since: "2025-11-10T15:00:00Z",
                stats: {
                    listings_count: 2,
                    reviews_count: 2,
                    rating: 4.3
                }
            },
            title: "Studio Near Gaines Street",
            description: "Showcase studio listing with a shorter lease window for students who need a compact sublease close to campus and downtown.",
            price: 1100,
            category: "sublease",
            condition: "n/a",
            listing_type: "sublease",
            price_period: "monthly",
            negotiable: false,
            contact_method: "phone",
            phone_number: "(850) 555-0172",
            location: "",
            address_text: "Gaines Street district",
            housing_type: "studio",
            bedrooms: 0,
            bathrooms: 1,
            furnished: true,
            utilities_included: true,
            parking_available: false,
            pet_friendly: false,
            roommates_allowed: false,
            lease_transfer_fee: null,
            availability_start: "2026-04-20",
            availability_end: "2026-08-15",
            sublease_notes: "Short-term showcase example for a studio layout with a direct phone-only contact preference.",
            image_urls: [mockupUrl("gaines_street.png")],
            created_at: "2026-03-19T19:05:00Z",
            status: "active",
            is_demo: true
        },
        {
            id: 900201,
            user_id: 910,
            seller_name: "Campus Tech Showcase",
            seller_email: "showcase+electronics@spearexchange.demo",
            seller_phone: "(850) 555-0110",
            seller_verified: 1,
            seller_created_at: "2025-09-01T12:00:00Z",
            seller: {
                profile_name: "Campus Tech Showcase",
                bio: "Generic showcase seller profile for electronics and everyday student gear.",
                is_verified: true,
                member_since: "2025-09-01T12:00:00Z",
                stats: { listings_count: 2, reviews_count: 9, rating: 4.8 }
            },
            title: "iPad Air for Notes and Classwork",
            description: "Showcase electronics listing for a student-friendly tablet setup used to preview the browse and detail experience for tech items.",
            price: 420,
            category: "electronics",
            condition: "like new",
            listing_type: "goods",
            price_period: "one_time",
            negotiable: true,
            contact_method: "both",
            phone_number: "(850) 555-0110",
            location: "Strozier Library",
            image_urls: [mockupUrl("ipad_air.png")],
            created_at: "2026-03-18T13:20:00Z",
            status: "active",
            is_demo: true
        },
        {
            id: 900202,
            user_id: 911,
            seller_name: "Study Stack Samples",
            seller_email: "showcase+textbooks@spearexchange.demo",
            seller_phone: "(850) 555-0111",
            seller_verified: 1,
            seller_created_at: "2025-09-10T10:00:00Z",
            seller: {
                profile_name: "Study Stack Samples",
                bio: "Generic showcase seller profile for books, study materials, and class resources.",
                is_verified: true,
                member_since: "2025-09-10T10:00:00Z",
                stats: { listings_count: 3, reviews_count: 5, rating: 4.6 }
            },
            title: "Organic Chemistry Textbook Bundle",
            description: "Demo listing for a used textbook set with notes and inserts, meant to make the academic category feel populated before real inventory arrives.",
            price: 65,
            category: "textbooks",
            condition: "good",
            listing_type: "goods",
            price_period: "one_time",
            negotiable: true,
            contact_method: "email",
            phone_number: "",
            location: "Dirac Library",
            image_urls: [mockupUrl("textbook_algos.png")],
            created_at: "2026-03-18T09:10:00Z",
            status: "active",
            is_demo: true
        },
        {
            id: 900203,
            user_id: 912,
            seller_name: "Dorm Setup Showcase",
            seller_email: "showcase+furniture@spearexchange.demo",
            seller_phone: "(850) 555-0112",
            seller_verified: 0,
            seller_created_at: "2025-10-05T10:00:00Z",
            seller: {
                profile_name: "Dorm Setup Showcase",
                bio: "Generic showcase seller profile for furniture and room setup ideas.",
                is_verified: false,
                member_since: "2025-10-05T10:00:00Z",
                stats: { listings_count: 2, reviews_count: 1, rating: 4.2 }
            },
            title: "Compact Dorm Desk and Chair Set",
            description: "Showcase furniture listing for a compact study setup, designed to fill out the room and apartment essentials category.",
            price: 140,
            category: "furniture",
            condition: "good",
            listing_type: "goods",
            price_period: "one_time",
            negotiable: false,
            contact_method: "both",
            phone_number: "(850) 555-0112",
            location: "West Pensacola pickup",
            image_urls: [mockupUrl("dorm_desk.png")],
            created_at: "2026-03-17T18:30:00Z",
            status: "active",
            is_demo: true
        },
        {
            id: 900204,
            user_id: 913,
            seller_name: "Garnet Closet Demo",
            seller_email: "showcase+clothing@spearexchange.demo",
            seller_phone: "(850) 555-0113",
            seller_verified: 1,
            seller_created_at: "2025-07-14T10:00:00Z",
            seller: {
                profile_name: "Garnet Closet Demo",
                bio: "Generic showcase seller profile for apparel and game-day gear.",
                is_verified: true,
                member_since: "2025-07-14T10:00:00Z",
                stats: { listings_count: 4, reviews_count: 11, rating: 4.7 }
            },
            title: "Vintage FSU Hoodie",
            description: "Demo apparel listing for game-day and campus style, used to showcase the clothing category in browse mode.",
            price: 38,
            category: "clothing",
            condition: "excellent",
            listing_type: "goods",
            price_period: "one_time",
            negotiable: true,
            contact_method: "both",
            phone_number: "(850) 555-0113",
            location: "CollegeTown",
            image_urls: [mockupUrl("fsu_hoodie.png")],
            created_at: "2026-03-17T12:15:00Z",
            status: "active",
            is_demo: true
        },
        {
            id: 900205,
            user_id: 914,
            seller_name: "Campus Rec Samples",
            seller_email: "showcase+sports@spearexchange.demo",
            seller_phone: "(850) 555-0114",
            seller_verified: 1,
            seller_created_at: "2025-08-03T10:00:00Z",
            seller: {
                profile_name: "Campus Rec Samples",
                bio: "Generic showcase seller profile for sports, fitness, and outdoor gear.",
                is_verified: true,
                member_since: "2025-08-03T10:00:00Z",
                stats: { listings_count: 2, reviews_count: 6, rating: 4.5 }
            },
            title: "Campus Cruiser Longboard",
            description: "Sample sports and recreation listing for student transport and casual weekend use around campus.",
            price: 72,
            category: "sports",
            condition: "good",
            listing_type: "goods",
            price_period: "one_time",
            negotiable: false,
            contact_method: "phone",
            phone_number: "(850) 555-0114",
            location: "Leach Recreation Center",
            image_urls: [mockupUrl("longboard.png")],
            created_at: "2026-03-16T17:20:00Z",
            status: "active",
            is_demo: true
        },
        {
            id: 900206,
            user_id: 915,
            seller_name: "Seminole Service Board",
            seller_email: "showcase+services@spearexchange.demo",
            seller_phone: "(850) 555-0115",
            seller_verified: 1,
            seller_created_at: "2025-06-20T10:00:00Z",
            seller: {
                profile_name: "Seminole Service Board",
                bio: "Generic showcase seller profile for student services and side-hustle offerings.",
                is_verified: true,
                member_since: "2025-06-20T10:00:00Z",
                stats: { listings_count: 5, reviews_count: 14, rating: 4.9 }
            },
            title: "Resume Review and Mock Interview Session",
            description: "Demo services listing that previews how non-physical offerings can still fit into the same marketplace flow.",
            price: 30,
            category: "services",
            condition: "new",
            listing_type: "goods",
            price_period: "one_time",
            negotiable: false,
            contact_method: "email",
            phone_number: "",
            location: "Virtual / on campus",
            image_urls: [svgDataUrl("Resume Review and Mock Interview Session", "#DB2777", "#4C1D95")],
            created_at: "2026-03-16T14:45:00Z",
            status: "active",
            is_demo: true
        },
        {
            id: 900207,
            user_id: 916,
            seller_name: "General Showcase Seller",
            seller_email: "showcase+other@spearexchange.demo",
            seller_phone: "(850) 555-0116",
            seller_verified: 0,
            seller_created_at: "2025-11-21T10:00:00Z",
            seller: {
                profile_name: "General Showcase Seller",
                bio: "Generic showcase profile used for miscellaneous marketplace examples.",
                is_verified: false,
                member_since: "2025-11-21T10:00:00Z",
                stats: { listings_count: 1, reviews_count: 0, rating: 0 }
            },
            title: "Starter Apartment Kitchen Bundle",
            description: "Demo listing for a mixed essentials bundle, used to give the general and miscellaneous category something visible in public browse mode.",
            price: 48,
            category: "other",
            condition: "good",
            listing_type: "goods",
            price_period: "one_time",
            negotiable: true,
            contact_method: "both",
            phone_number: "(850) 555-0116",
            location: "Southwood area",
            image_urls: [mockupUrl("kitchen_bundle.png")],
            created_at: "2026-03-15T15:00:00Z",
            status: "active",
            is_demo: true
        }
    ];

    function cloneDemoListing(listing) {
        return JSON.parse(JSON.stringify(listing));
    }

    window.DEMO_LISTINGS = demoListings.map(cloneDemoListing);
    window.findDemoListingById = function findDemoListingById(id) {
        const normalizedId = Number(id);
        const listing = demoListings.find(item => item.id === normalizedId);
        return listing ? cloneDemoListing(listing) : null;
    };
    window.getDemoListingsByUserId = function getDemoListingsByUserId(userId, excludeId) {
        const normalizedUserId = Number(userId);
        const normalizedExcludeId = Number(excludeId);
        return demoListings
            .filter(item => item.user_id === normalizedUserId && item.id !== normalizedExcludeId)
            .map(cloneDemoListing);
    };
})();
