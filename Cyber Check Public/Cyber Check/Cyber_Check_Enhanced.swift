//
//  Cyber_Check_Enhanced.swift
//  Cyber Check
//
//  Created by Saketh Pondugula on 7/8/25.
//
// Cyber Check Enhanced - Full SwiftUI App
// Includes: Questionnaire Skip Logic, Password Vault w/ Puzzle 2FA, Cyber Quiz, Gemini AI Chat

/*import SwiftUI

@main
struct CyberCheckEnhancedApp: App {
    var body: some Scene {
        WindowGroup {
            EnhancedHomeView()
        }
    }
}

// MARK: - Global Navigation State
class NavigationCoordinator: ObservableObject {
    @Published var showQuestionnaire = false
    @Published var showPasswordVault = false
    @Published var showGeminiChat = false
    @Published var showCyberQuiz = false
}

// MARK: - Enhanced Home View
struct EnhancedHomeView: View {
    @StateObject private var coordinator = NavigationCoordinator()
    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let bgColor = Color(red: 0.08, green: 0.08, blue: 0.15)

    var body: some View {
        NavigationStack {
            ZStack {
                bgColor.ignoresSafeArea()
                VStack(spacing: 30) {
                    Spacer()
                    Text("Cyber-Check Pro")
                        .font(.largeTitle.bold())
                        .foregroundColor(accentColor)
                    VStack(spacing: 20) {
                        Button("URL Safety Questionnaire") { coordinator.showQuestionnaire = true }
                        Button("Password Vault") { coordinator.showPasswordVault = true }
                        Button("Ask Gemini AI") { coordinator.showGeminiChat = true }
                        Button("Cybersecurity Quiz") { coordinator.showCyberQuiz = true }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(accentColor)
                    Spacer()
                }
                .padding()
                .navigationDestination(isPresented: $coordinator.showQuestionnaire) {
                    QuestionnaireView()
                }
                .navigationDestination(isPresented: $coordinator.showPasswordVault) {
                    Puzzle2FAView()
                }
                .navigationDestination(isPresented: $coordinator.showGeminiChat) {
                    GeminiChatView()
                }
                .navigationDestination(isPresented: $coordinator.showCyberQuiz) {
                    CyberQuizView()
                }
            }
        }
    }
}

// MARK: - Questionnaire View with Skip Logic
struct QuestionnaireView: View {
    @Environment(\.dismiss) var dismiss
    @State private var questions: [String] = [
        "Does the site look suspicious?",
        "Is it filled with ads?",
        "Did it ask for personal info unexpectedly?"
    ]
    @State private var answers: [Int?] = Array(repeating: nil, count: 3)

    var body: some View {
        VStack(spacing: 20) {
            Text("URL Safety Questionnaire")
                .font(.title2.bold())
            ForEach(0..<questions.count, id: \.self) { i in
                VStack(alignment: .leading) {
                    Text(questions[i])
                    Picker("", selection: $answers[i]) {
                        Text("Yes").tag(0 as Int?)
                        Text("No").tag(1 as Int?)
                        Text("Not Sure").tag(2 as Int?)
                    }
                    .pickerStyle(.segmented)
                }
            }

            let allUnanswered = answers.allSatisfy { $0 == nil }
            Button(allUnanswered ? "Skip Questionnaire" : "Submit") {
                dismiss()
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
    }
}

// MARK: - Password Vault 2FA Puzzle View
struct Puzzle2FAView: View {
    @State private var userInput = ""
    @State private var isUnlocked = false
    let puzzleQuestion = "What was the name of your first pet?"
    let puzzleAnswer = "tiger" // Change this to something user-defined in production

    var body: some View {
        VStack(spacing: 20) {
            if isUnlocked {
                PasswordVaultView()
            } else {
                Text("2FA Challenge")
                    .font(.title2.bold())
                Text(puzzleQuestion)
                TextField("Your Answer", text: $userInput)
                    .textFieldStyle(.roundedBorder)
                Button("Unlock") {
                    if userInput.lowercased().trimmingCharacters(in: .whitespacesAndNewlines) == puzzleAnswer.lowercased() {
                        isUnlocked = true
                    }
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding()
    }
}

// MARK: - Password Vault
struct PasswordVaultView: View {
    @AppStorage("vault_passwords") var passwordList: String = ""
    @State private var newSite = ""
    @State private var newPassword = ""

    var body: some View {
        VStack(spacing: 15) {
            Text("Password Vault")
                .font(.title2.bold())
            TextField("Site", text: $newSite)
                .textFieldStyle(.roundedBorder)
            TextField("Password", text: $newPassword)
                .textFieldStyle(.roundedBorder)
            Button("Save") {
                let entry = "\(newSite):\(newPassword)"
                passwordList += "\n" + entry
                newSite = ""
                newPassword = ""
            }
            .buttonStyle(.borderedProminent)

            Divider()
            ScrollView {
                Text(passwordList)
                    .font(.system(.body, design: .monospaced))
                    .padding()
            }
        }
        .padding()
    }
}

// MARK: - Gemini AI Chat View (Simulated)
struct GeminiChatView: View {
    @Environment(\.dismiss) var dismiss
    @State private var userText = ""
    @State private var botResponse = ""

    var body: some View {
        VStack(spacing: 20) {
            Text("Gemini AI Chat")
                .font(.title2.bold())
            TextEditor(text: $userText)
                .frame(height: 100)
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.gray))
            Button("Ask Gemini") {
                botResponse = "Analyzing your situation... (simulated response)"
            }
            .buttonStyle(.borderedProminent)
            ScrollView {
                Text(botResponse)
                    .padding()
            }
            Spacer()
        }
        .padding()
    }
}

// MARK: - Cyber Quiz Mini Game
struct CyberQuizView: View {
    @Environment(\.dismiss) var dismiss
    @State private var score = 0
    @State private var current = 0
    let questions = [
        ("What does HTTPS stand for?", "Secure version of HTTP"),
        ("What should you avoid clicking in a suspicious email?", "Links"),
        ("Is 'password123' a strong password?", "No")
    ]
    @State private var userAnswer = ""
    @State private var showResult = false

    var body: some View {
        VStack(spacing: 20) {
            if current < questions.count {
                Text(questions[current].0)
                TextField("Answer", text: $userAnswer)
                    .textFieldStyle(.roundedBorder)
                Button("Submit") {
                    if userAnswer.lowercased().contains(questions[current].1.lowercased()) {
                        score += 1
                    }
                    userAnswer = ""
                    current += 1
                }
            } else {
                Text("Quiz Complete!")
                Text("Your Score: \(score)/\(questions.count)")
                Button("Done") { dismiss() }
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding()
    }
}
*/
