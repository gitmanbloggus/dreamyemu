import SwiftUI

@main
struct DreamyemuApp: App {
    @StateObject private var modelo = DreamyemuModelo()

    var body: some Scene {
        WindowGroup {
            BibliotecaView(modelo: modelo)
                .preferredColorScheme(.dark)
        }
    }
}
