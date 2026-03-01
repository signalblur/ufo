import Testing
@testable import UFOLib

@Suite("Help Text")
struct HelpTextTests {
    @Test("Renders known topics")
    func renderKnownTopics() {
        let root = HelpText.render(topic: nil)
        #expect(root.contains("UFO - managed local keychain CLI"))
        #expect(root.contains("ufo --env <VAR>"))
        #expect(HelpText.render(topic: "").contains("UFO - managed local keychain CLI"))
        #expect(HelpText.render(topic: "ufo").contains("UFO - managed local keychain CLI"))
        #expect(HelpText.render(topic: "keychain").contains("ufo keychain <subcommand>"))
        #expect(HelpText.render(topic: "keychain create").contains("ufo keychain create"))
        #expect(HelpText.render(topic: "keychain harden").contains("ufo keychain harden"))
        #expect(HelpText.render(topic: "keychain list").contains("ufo keychain list"))
        #expect(HelpText.render(topic: "keychain delete").contains("ufo keychain delete"))
        #expect(HelpText.render(topic: "secret").contains("ufo secret <subcommand>"))
        #expect(HelpText.render(topic: "secret set").contains("ufo secret set"))
        #expect(HelpText.render(topic: "secret run").contains("ufo secret run"))
        #expect(HelpText.render(topic: "secret get").contains("ufo secret get"))
        #expect(HelpText.render(topic: "secret remove").contains("ufo secret remove"))
        #expect(HelpText.render(topic: "secret search").contains("ufo secret search"))
        #expect(HelpText.render(topic: "doctor").contains("ufo doctor"))
        #expect(HelpText.render(topic: "help").contains("ufo help"))
    }

    @Test("Renders unknown topic fallback")
    func renderUnknownTopicFallback() {
        let rendered = HelpText.render(topic: "mystery")
        #expect(rendered.contains("Unknown help topic 'mystery'."))
        #expect(rendered.contains("Usage:"))
    }
}
