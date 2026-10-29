// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SUITE'S HOST CONNECTOR: busbar-test-kit's `conformance_host!` (the host this file used to carry a rendered copy of lives there now).

busbar_test_kit::conformance_host! {
    far_end: "localhost:58940",
    doors: [
        ("tcp", busbar_transport_tcp::door::MACRO_DOOR),
        ("http", busbar_transport_http::door::MACRO_DOOR),
    ],
    http_need: true,
}
