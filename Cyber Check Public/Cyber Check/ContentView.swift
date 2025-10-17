import SwiftUI
import CoreML
import Combine
import CryptoKit // For SHA256 hashing and AES GCM encryption
import Foundation
import Security // For Keychain access
import CommonCrypto // For PBKDF2 key derivation for master password
// Removed LocalAuthentication as biometrics feature is removed

// MARK: - Shared Navigation State
class NavigationState: ObservableObject {
    @Published var isURLSubmitted = false
    @Published var isQuestionnaireSubmitted = false
    @Published var isAIResultSafe: Bool? = nil
    @Published var chatGPTResultSafe: AssessmentResult? = nil
    @Published var skipAIURLCheck = false
    @Published var assessmentResult: AssessmentResult? = nil
    @Published var showURLCheck = false
    @Published var showEmailCheck = false
    @Published var showPasswordMaker = false
    @Published var showPasswordStorage = false
    @Published var showMiniQuiz = false
    @Published var showGeminiChat = false
}

// MARK: - KeychainManager
// Manages secure storage of sensitive data (like master password hash) in Keychain.
class KeychainManager {
    static let service = "Congressional-App-Challenge.Cyber-Check"
    static let masterPasswordAccount = "masterPasswordHash"

    static func save(key: String, data: Data) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked // Item is accessible only while the device is unlocked
        ]
        // Delete any existing item before adding to ensure it's up-to-date
        SecItemDelete(query as CFDictionary)
        return SecItemAdd(query as CFDictionary, nil)
    }

    static func load(key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: kCFBooleanTrue!, // Request data back
            kSecMatchLimit as String: kSecMatchLimitOne // Only one match
        ]

        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)

        return status == noErr ? dataTypeRef as? Data : nil
    }

    static func delete(key: String) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        return SecItemDelete(query as CFDictionary)
    }
}

// MARK: - Custom Button Styles
struct CyberButtonStyle: ButtonStyle {
    var accentColor: Color = Color(red: 0.3, green: 0.8, blue: 0.95) // Centralized color

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline)
            .padding(.vertical, 12)
            .padding(.horizontal, 25)
            .background(
                RoundedRectangle(cornerRadius: 15)
                    .fill(accentColor.opacity(configuration.isPressed ? 0.7 : 1.0))
                    .shadow(color: accentColor.opacity(0.4), radius: 5, x: 0, y: 5)
            )
            .foregroundColor(.white)
            .scaleEffect(configuration.isPressed ? 0.95 : 1.0)
            .animation(.spring(), value: configuration.isPressed)
    }
}

struct SmallCyberBackButton: ButtonStyle {
    var accentColor: Color = Color(red: 0.3, green: 0.8, blue: 0.95) // Centralized color
    var backgroundColor: Color = Color(red: 0.12, green: 0.12, blue: 0.22).opacity(0.3) // Centralized color

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.caption)
            .padding(.vertical, 8)
            .padding(.horizontal, 15)
            .background(backgroundColor.opacity(configuration.isPressed ? 0.7 : 1.0))
            .foregroundColor(accentColor)
            .cornerRadius(10)
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .stroke(accentColor, lineWidth: 1)
            )
            .scaleEffect(configuration.isPressed ? 0.95 : 1.0)
            .animation(.spring(), value: configuration.isPressed)
    }
}

// MARK: - Assessment Result Enum
enum AssessmentResult: Codable {
    case safe
    case unsafe
    case suspicious
}

// MARK: - Question Model (for URL Questionnaire)
struct Question: Identifiable {
    let id = UUID()
    let text: String
    var answer: QuestionAnswer? = nil
}

enum QuestionAnswer: Codable {
    case yes, no, notSure
}

// MARK: - Learn More Text Generator
enum LearnMoreContentType { // Moved declaration here
    case url
    case email
    case general // For quiz results etc.
}

func LearnMoreText(for result: AssessmentResult, type: LearnMoreContentType) -> String {
    switch type {
    case .url:
        switch result {
        case .safe:
            return "Safe URLs are free from malware, phishing, or scams. Always check for HTTPS, legitimate domains, and be cautious of redirects. Verify sender and content."
        case .unsafe:
            return "Unsafe URLs are confirmed threats like phishing or malware. They aim to steal data or harm your device. Avoid them completely."
        case .suspicious:
            return "Suspicious URLs may use deceptive links, unusual characters, or redirect to unexpected sites. Verify the domain carefully before clicking or sharing."
        }
    case .email:
        switch result {
        case .safe:
            return "Safe emails lack phishing signs or malicious links. Always check sender identity, grammar, and avoid clicking unexpected attachments or links."
        case .unsafe:
            return "Unsafe emails are confirmed malicious. They often contain direct threats, fake invoices, or links to known scam sites. Delete and block sender."
        case .suspicious:
            return "Suspicious emails often contain urgent requests, generic greetings, or unusual sender addresses. Verify details before responding or clicking."
        }
    case .general:
        switch result {
        case .safe:
            return "Great job! You have a good understanding of online safety. Keep practicing secure habits."
        case .unsafe:
            return "It seems there are some areas where you could improve your cybersecurity knowledge. Stay vigilant and review safety tips!"
        case .suspicious:
            return "You're on the right track, but some situations might still be tricky. Continue learning and be cautious online."
        }
    }
}

// MARK: - AI Model Integration and Assessment Result Functions
// Ensure you have URL_Diagnoser_1.mlmodel in your project
func predictURLSafety(from urlString: String) -> Bool? {
    guard let url = URL(string: urlString), let host = url.host else {
        return nil
    }

    let length = Int64(urlString.count)
    let has_https = Int64(url.scheme?.lowercased() == "https" ? 1 : 0)
    let num_dots = Int64(urlString.filter { $0 == "." }.count)
    let has_ip = Int64(host.split(separator: ".").allSatisfy { $0.allSatisfy(\Character.isNumber) } ? 1 : 0)
    let path_length = Int64(url.path.count)

    do {
        // Make sure URL_Diagnoser_1 is correctly integrated into your project.
        // It should be a CoreML model.
        let model = try URL_Diagnoser_1(configuration: .init())
        let input = URL_Diagnoser_1Input(
            length: length,
            has_https: has_https,
            num_dots: num_dots,
            has_ip: has_ip,
            path_length: path_length
        )
        let prediction = try model.prediction(input: input)

        return prediction.Label == 1 // Assuming 1 means safe, 0 means unsafe
    } catch {
        print("Prediction failed: \(error)")
        return nil
    }
}

// MARK: - Gemini API Structures
struct GeminiRequestBody: Codable {
    let contents: [Content]
    let generationConfig: GenerationConfig?
    let safetySettings: [SafetySetting]?

    struct Content: Codable {
        let role: String? // Added role property
        let parts: [Part]

        // Custom initializer to easily create Content objects
        init(role: String? = nil, parts: [Part]) {
            self.role = role
            self.parts = parts
        }
    }

    struct Part: Codable {
        let text: String
    }

    struct GenerationConfig: Codable {
        let temperature: Double?
        let topP: Double?
        let topK: Int?
        let maxOutputTokens: Int?
        let stopSequences: [String]?

        init(temperature: Double? = nil, topP: Double? = nil, topK: Int? = nil, maxOutputTokens: Int? = nil, stopSequences: [String]? = nil) {
            self.temperature = temperature
            self.topP = topP
            self.topK = topK
            self.maxOutputTokens = maxOutputTokens
            self.stopSequences = stopSequences
        }
    }

    struct SafetySetting: Codable {
        let category: String
        let threshold: String
    }
}

struct GeminiResponseBody: Codable {
    let candidates: [Candidate]?
    let promptFeedback: PromptFeedback?

    struct Candidate: Codable {
        let content: Content
        let finishReason: String?
        let index: Int?
        let safetyRatings: [SafetyRating]?

        struct Content: Codable {
            let parts: [Part]?
            let role: String?
        }

        struct Part: Codable {
            let text: String?
        }
    }

    struct PromptFeedback: Codable {
        let safetyRatings: [SafetyRating]?
    }

    struct SafetyRating: Codable {
        let category: String
        let probability: String
    }
}

// MARK: - Gemini API Call Functions
func callGeminiAPI(for text: String, completion: @escaping (AssessmentResult?) -> Void) {
    guard let apiKey = Bundle.main.infoDictionary?["GEMINI_API_KEY"] as? String else {
        print("Gemini API Key not found. Please set GEMINI_API_KEY in Info.plist or environment variables.")
        DispatchQueue.main.async { completion(nil) }
        return
    }

    let urlString = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=\(apiKey)"
    guard let url = URL(string: urlString) else {
        print("Invalid URL for Gemini API")
        DispatchQueue.main.async { completion(nil) }
        return
    }

    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.addValue("application/json", forHTTPHeaderField: "Content-Type")

    let prompt = """
    Analyze the following text, which could be an email, message, or description of online content.
    Determine its safety based on characteristics of phishing, scams, malware, suspicious links, unusual requests, or general untrustworthiness.

    Respond concisely with *only one word*:
    - 'Safe' if the text appears to be genuinely safe with no red flags.
    - 'Unsafe' if it clearly indicates a scam, phishing attempt, malware distribution, or highly malicious content.
    - 'Suspicious' if it contains some red flags, unusual elements, or prompts for risky actions, but isn't definitively malicious.

    Do not include any other text, explanations, or punctuation.

    Text to analyze: \"\(text)\"
    """

    let body = GeminiRequestBody(
        contents: [
            GeminiRequestBody.Content(parts: [GeminiRequestBody.Part(text: prompt)])
        ],
        generationConfig: GeminiRequestBody.GenerationConfig(
            temperature: 0.1,
            topP: 1.0,
            topK: 1,
            maxOutputTokens: 1000
        ),
        safetySettings: nil
    )

    do {
        let jsonData = try JSONEncoder().encode(body)
        request.httpBody = jsonData

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                print("Network error calling Gemini API: \(error.localizedDescription)")
                DispatchQueue.main.async { completion(nil) }
                return
            }

            guard let data = data else {
                print("No data received from Gemini API")
                DispatchQueue.main.async { completion(nil) }
                return
            }

            if let httpResponse = response as? HTTPURLResponse,
               httpResponse.statusCode != 200 {
                print("Gemini API HTTP Error: \(httpResponse.statusCode)")
                if let errorResponseString = String(data: data, encoding: .utf8) {
                    print("Error Response Body: \(errorResponseString)")
                }
                DispatchQueue.main.async { completion(nil) }
                return
            }

            if let jsonString = String(data: data, encoding: .utf8) {
                print("Gemini Raw Response: \(jsonString)")
            }

            do {
                let geminiResponse = try JSONDecoder().decode(GeminiResponseBody.self, from: data)

                if let promptFeedback = geminiResponse.promptFeedback, let safetyRatings = promptFeedback.safetyRatings, !safetyRatings.isEmpty {
                    print("Gemini API: Prompt was blocked due to safety concerns.")
                    DispatchQueue.main.async { completion(.unsafe) } // Treat blocked prompts as unsafe for user safety
                    return
                }

                if let firstCandidate = geminiResponse.candidates?.first {
                    if let responseSafetyRatings = firstCandidate.safetyRatings, !responseSafetyRatings.isEmpty {
                        print("Gemini API: Response was blocked due to safety concerns from model output.")
                        DispatchQueue.main.async { completion(.unsafe) } // Treat blocked responses as unsafe
                        return
                    }

                    if let responseText = firstCandidate.content.parts?.first?.text {
                        let trimmedResponse = responseText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

                        if trimmedResponse == "safe" {
                            print("Gemini API response: 'Safe'")
                            DispatchQueue.main.async { completion(.safe) }
                        } else if trimmedResponse == "unsafe" {
                            print("Gemini API response: 'Unsafe'")
                            DispatchQueue.main.async { completion(.unsafe) }
                        } else if trimmedResponse == "suspicious" {
                            print("Gemini API response: 'Suspicious'")
                            DispatchQueue.main.async { completion(.suspicious) }
                        } else {
                            print("Gemini response was unexpected: '\(trimmedResponse)'")
                            DispatchQueue.main.async { completion(nil) }
                        }
                    } else {
                        print("Gemini response did not contain expected content (no parts in candidate). Likely filtered or incomplete.")
                        DispatchQueue.main.async { completion(.suspicious) } // Treat as suspicious if content is missing
                    }
                } else {
                    print("Gemini response did not contain any candidates.")
                    DispatchQueue.main.async { completion(nil) }
                }

            } catch {
                print("Failed to decode Gemini API response: \(error)")
                DispatchQueue.main.async { completion(nil) }
            }
        }.resume()
    } catch {
        print("Failed to encode Gemini API request body: \(error)")
        DispatchQueue.main.async { completion(nil) }
    }
}

// NEW: Gemini AI Chat Specific API Call
func callGeminiChatAPI(for message: String, history: [[String: String]], completion: @escaping (String?, AssessmentResult?) -> Void) {
    guard let apiKey = Bundle.main.infoDictionary?["GEMINI_API_KEY"] as? String else {
        print("Gemini API Key not found. Please set GEMINI_API_KEY in Info.plist or environment variables.")
        DispatchQueue.main.async { completion("Error: API Key missing.", nil) }
        return
    }

    let urlString = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=\(apiKey)"
    guard let url = URL(string: urlString) else {
        print("Invalid URL for Gemini API")
        DispatchQueue.main.async { completion("Error: Invalid API URL.", nil) }
        return
    }

    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.addValue("application/json", forHTTPHeaderField: "Content-Type")

    // Construct conversation history for Gemini API
    var contents: [GeminiRequestBody.Content] = []
    for turn in history {
        if let role = turn["role"], let text = turn["text"] {
            // Correctly create Content with role and parts
            contents.append(GeminiRequestBody.Content(role: role, parts: [GeminiRequestBody.Part(text: text)]))
        }
    }
    // Add the current user message with the "user" role
    contents.append(GeminiRequestBody.Content(role: "user", parts: [GeminiRequestBody.Part(text: message)]))

    let body = GeminiRequestBody(
        contents: contents,
        generationConfig: GeminiRequestBody.GenerationConfig(
            temperature: 0.7, // More creative for chat
            topP: 1.0,
            topK: 40,
            maxOutputTokens: 2500
        ),
        safetySettings: [ // More relaxed safety for open chat, but still present
            GeminiRequestBody.SafetySetting(category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_NONE"),
            GeminiRequestBody.SafetySetting(category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_NONE"),
            GeminiRequestBody.SafetySetting(category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_NONE"),
            GeminiRequestBody.SafetySetting(category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold: "BLOCK_NONE"),
        ]
    )

    do {
        let jsonData = try JSONEncoder().encode(body)
        request.httpBody = jsonData

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                print("Network error calling Gemini chat API: \(error.localizedDescription)")
                DispatchQueue.main.async { completion("Network error. Please try again.", nil) }
                return
            }

            guard let data = data else {
                print("No data received from Gemini chat API")
                DispatchQueue.main.async { completion("No response data.", nil) }
                return
            }

            if let httpResponse = response as? HTTPURLResponse,
               httpResponse.statusCode != 200 {
                print("Gemini chat API HTTP Error: \(httpResponse.statusCode)")
                if let errorResponseString = String(data: data, encoding: .utf8) {
                    print("Error Response Body: \(errorResponseString)")
                }
                DispatchQueue.main.async { completion("API error (\(httpResponse.statusCode)).", nil) }
                return
            }

            do {
                let geminiResponse = try JSONDecoder().decode(GeminiResponseBody.self, from: data)

                if let promptFeedback = geminiResponse.promptFeedback, let safetyRatings = promptFeedback.safetyRatings, !safetyRatings.isEmpty {
                    print("Gemini API: Prompt was blocked due to safety concerns for chat.")
                    DispatchQueue.main.async { completion("Your message was flagged by safety systems. Please try rephrasing.", .unsafe) }
                    return
                }

                if let firstCandidate = geminiResponse.candidates?.first,
                   let responseText = firstCandidate.content.parts?.first?.text {
                    DispatchQueue.main.async { completion(responseText, .safe) } // Assuming chat responses are "safe" in context
                } else {
                    print("Gemini chat response did not contain expected content.")
                    DispatchQueue.main.async { completion("Could not get a clear response from AI. Please try again.", .suspicious) }
                }

            } catch {
                print("Failed to decode Gemini chat API response: \(error)")
                DispatchQueue.main.async { completion("Failed to process AI response.", nil) }
            }
        }.resume()
    } catch {
        print("Failed to encode Gemini chat API request body: \(error)")
        DispatchQueue.main.async { completion("Error encoding request.", nil) }
    }
}

// MARK: - Result Screen (for URL Questionnaire)
struct ResultView: View {
    let assessmentResult: AssessmentResult?
    @ObservedObject var navState: NavigationState

    let primaryBackgroundColor = Color(red: 0.08, green: 0.08, blue: 0.15)
    let secondaryBackgroundColor = Color(red: 0.12, green: 0.12, blue: 0.22)
    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let textColor = Color.white

    var body: some View {
        ZStack {
            primaryBackgroundColor
                .ignoresSafeArea()

            VStack(spacing: 40) {
                switch assessmentResult {
                case .safe:
                    Image(systemName: "checkmark.shield.fill")
                        .resizable()
                        .foregroundColor(Color.green.opacity(0.8))
                        .frame(width: 150, height: 150)
                        .shadow(color: Color.green.opacity(0.4), radius: 12)
                    Text("Safe!")
                        .font(.system(size: 48, weight: .bold, design: .rounded))
                        .foregroundColor(textColor)
                        .shadow(color: Color.green.opacity(0.5), radius: 8)
                    Text(LearnMoreText(for: .safe, type: .url))
                        .font(.system(size: 15, weight: .regular, design: .rounded))
                        .foregroundColor(textColor.opacity(0.8))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                case .unsafe:
                    Image(systemName: "exclamationmark.triangle.fill")
                        .resizable()
                        .foregroundColor(Color.red.opacity(0.8))
                        .frame(width: 150, height: 150)
                        .shadow(color: Color.red.opacity(0.4), radius: 12)
                    Text("Unsafe!")
                        .font(.system(size: 48, weight: .bold, design: .rounded))
                        .foregroundColor(textColor)
                        .shadow(color: Color.red.opacity(0.5), radius: 8)
                    Text(LearnMoreText(for: .unsafe, type: .url))
                        .font(.system(size: 15, weight: .regular, design: .rounded))
                        .foregroundColor(textColor.opacity(0.8))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                case .suspicious:
                    Image(systemName: "questionmark.circle.fill")
                        .resizable()
                        .foregroundColor(Color.orange.opacity(0.8))
                        .frame(width: 150, height: 150)
                        .shadow(color: Color.orange.opacity(0.4), radius: 12)
                    Text("Suspicious!")
                        .font(.system(size: 48, weight: .bold, design: .rounded))
                        .foregroundColor(textColor)
                        .shadow(color: Color.orange.opacity(0.5), radius: 8)
                    Text(LearnMoreText(for: .suspicious, type: .url))
                        .font(.system(size: 15, weight: .regular, design: .rounded))
                        .foregroundColor(textColor.opacity(0.8))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                case .none:
                    Image(systemName: "xmark.octagon.fill")
                        .resizable()
                        .foregroundColor(Color.gray.opacity(0.7))
                        .frame(width: 150, height: 150)
                        .shadow(color: Color.gray.opacity(0.3), radius: 10)
                    Text("Unknown Result")
                        .font(.system(size: 48, weight: .bold, design: .rounded))
                        .foregroundColor(textColor)
                        .shadow(color: Color.gray.opacity(0.3), radius: 8)
                    Text("Could not determine safety. Exercise extreme caution or avoid completely.")
                        .font(.system(size: 15, weight: .regular, design: .rounded))
                        .foregroundColor(textColor.opacity(0.8))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }

                Button("Back to Start") {
                    navState.isQuestionnaireSubmitted = false
                    navState.isURLSubmitted = false
                    navState.chatGPTResultSafe = nil
                    navState.isAIResultSafe = nil
                    navState.skipAIURLCheck = false
                    navState.assessmentResult = nil
                    navState.showURLCheck = false
                    navState.showEmailCheck = false
                    navState.showPasswordMaker = false
                    navState.showPasswordStorage = false
                    navState.showMiniQuiz = false
                    navState.showGeminiChat = false
                }
                .buttonStyle(CyberButtonStyle(accentColor: accentColor))
                .padding()

                Button("Retake Questionnaire") {
                    navState.isQuestionnaireSubmitted = false
                    navState.chatGPTResultSafe = nil
                    navState.assessmentResult = nil
                }
                .buttonStyle(CyberButtonStyle(accentColor: accentColor))
                .padding()
            }
            .padding()
            .background(secondaryBackgroundColor, in: RoundedRectangle(cornerRadius: 25))
            .padding()
        }
        .navigationBarBackButtonHidden(true)
    }
}

// MARK: - Email Check View
struct EmailCheckView: View {
    @ObservedObject var navState: NavigationState
    @State private var emailText: String = ""
    @State private var isLoadingGeminiCheck = false
    @State private var geminiEmailResult: AssessmentResult? = nil

    let primaryBackgroundColor = Color(red: 0.08, green: 0.08, blue: 0.15)
    let secondaryBackgroundColor = Color(red: 0.12, green: 0.12, blue: 0.22)
    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let textColor = Color.white

    var body: some View {
        ZStack {
            primaryBackgroundColor
                .ignoresSafeArea()

            VStack(spacing: 30) {
                Text("Check Email Safety")
                    .font(.system(size: 38, weight: .bold, design: .rounded))
                    .foregroundColor(textColor)
                    .shadow(color: secondaryBackgroundColor.opacity(0.5), radius: 8)
                    .padding(.top, 100)

                TextField("Enter email content here...", text: $emailText, axis: .vertical)
                    .padding()
                    .background(
                        RoundedRectangle(cornerRadius: 15)
                            .fill(secondaryBackgroundColor)
                            .stroke(accentColor, lineWidth: 2)
                    )
                    .foregroundColor(textColor)
                    .accentColor(accentColor)
                    .font(.system(size: 18, weight: .semibold, design: .rounded))
                    .frame(height: 150)
                    .padding(.horizontal)

                Button {
                    isLoadingGeminiCheck = true
                    Task {
                        await withCheckedContinuation { continuation in
                            callGeminiAPI(for: emailText) { result in
                                geminiEmailResult = result
                                continuation.resume()
                            }
                        }
                        isLoadingGeminiCheck = false
                    }
                } label: {
                    if isLoadingGeminiCheck {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: textColor))
                            .padding(.vertical, 8)
                            .padding(.horizontal, 15)
                    } else {
                        Text("Analyze Email")
                            .font(.system(size: 20, weight: .bold, design: .rounded))
                            .padding(.vertical, 8)
                            .padding(.horizontal, 15)
                    }
                }
                .disabled(emailText.isEmpty || isLoadingGeminiCheck)
                .buttonStyle(CyberButtonStyle(accentColor: accentColor))
                .padding(.horizontal)

                if let result = geminiEmailResult {
                    VStack(spacing: 10) {
                        switch result {
                        case .safe:
                            Image(systemName: "checkmark.circle.fill")
                                .resizable()
                                .frame(width: 50, height: 50)
                                .foregroundColor(.green)
                            Text("Assessment: Safe!")
                                .font(.system(size: 24, weight: .semibold, design: .rounded))
                                .foregroundColor(.green)
                            Text(LearnMoreText(for: .safe, type: .email))
                                .font(.system(size: 15, weight: .regular, design: .rounded))
                                .foregroundColor(textColor.opacity(0.8))
                                .multilineTextAlignment(.center)
                                .padding(.horizontal)
                        case .unsafe:
                            Image(systemName: "xmark.octagon.fill")
                                .resizable()
                                .frame(width: 50, height: 50)
                                .foregroundColor(.red)
                            Text("Assessment: Unsafe!")
                                .font(.system(size: 24, weight: .semibold, design: .rounded))
                                .foregroundColor(.red)
                            Text(LearnMoreText(for: .unsafe, type: .email))
                                .font(.system(size: 15, weight: .regular, design: .rounded))
                                .foregroundColor(textColor.opacity(0.8))
                                .multilineTextAlignment(.center)
                                .padding(.horizontal)
                        case .suspicious:
                            Image(systemName: "questionmark.circle.fill")
                                .resizable()
                                .frame(width: 50, height: 50)
                                .foregroundColor(.orange)
                            Text("Assessment: Suspicious!")
                                .font(.system(size: 24, weight: .semibold, design: .rounded))
                                .foregroundColor(.orange)
                            Text(LearnMoreText(for: .suspicious, type: .email))
                                .font(.system(size: 15, weight: .regular, design: .rounded))
                                .foregroundColor(textColor.opacity(0.8))
                                .multilineTextAlignment(.center)
                                .padding(.horizontal)
                        }
                    }
                    .padding(.top, 20)
                }

                Spacer()

                Button("Back to Home") {
                    navState.showEmailCheck = false
                    emailText = ""
                    geminiEmailResult = nil
                }
                .buttonStyle(SmallCyberBackButton(accentColor: accentColor, backgroundColor: secondaryBackgroundColor.opacity(0.3)))
                .padding(.bottom, 20)
            }
        }
        .navigationBarBackButtonHidden(true)
    }
}

// MARK: - URL Entry View
struct ContentView: View {
    @ObservedObject var navState: NavigationState
    @State private var urlText = ""

    let primaryBackgroundColor = Color(red: 0.08, green: 0.08, blue: 0.15)
    let secondaryBackgroundColor = Color(red: 0.12, green: 0.12, blue: 0.22)
    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let textColor = Color.white

    var body: some View {
        ZStack {
            primaryBackgroundColor
                .ignoresSafeArea()

            VStack(spacing: 40) {
                VStack(spacing: 20) {
                    Text("Enter a URL")
                        .font(.system(size: 38, weight: .bold, design: .rounded))
                        .foregroundColor(textColor)
                        .shadow(color: accentColor.opacity(0.5), radius: 8)

                    TextField("https://example.com", text: $urlText)
                        .textFieldStyle(PlainTextFieldStyle())
                        .padding()
                        .background(secondaryBackgroundColor, in: RoundedRectangle(cornerRadius: 15))
                        .foregroundColor(textColor)
                        .accentColor(accentColor)
                        .overlay(
                            RoundedRectangle(cornerRadius: 15)
                                .stroke(accentColor, lineWidth: 2)
                        )
                        .padding(.horizontal)
                }
                .padding(.top, 100)

                Button("Continue") {
                    if let url = URL(string: urlText), url.scheme?.lowercased() == "https" {
                        navState.isAIResultSafe = true
                        navState.skipAIURLCheck = true
                        print("URL is HTTPS, local AI model automatically skipped and marked as safe.")
                        navState.isURLSubmitted = true
                    } else if let result = predictURLSafety(from: urlText) {
                        navState.isAIResultSafe = result
                        navState.skipAIURLCheck = false
                        print("Local AI Model prediction (for URL): \(result ? "Safe" : "Unsafe")")
                        navState.isURLSubmitted = true
                    } else {
                        navState.isAIResultSafe = nil
                        navState.skipAIURLCheck = false
                        print("Prediction failed or invalid URL for local AI model. Cannot proceed.")
                        navState.isURLSubmitted = false // Keep user on this screen if prediction fails
                    }
                }
                .disabled(urlText.isEmpty)
                .buttonStyle(CyberButtonStyle(accentColor: accentColor))
                .padding(.horizontal)

                Button("Back to Home") {
                    navState.showURLCheck = false
                    urlText = ""
                    navState.isURLSubmitted = false
                    navState.isAIResultSafe = nil
                    navState.skipAIURLCheck = false
                    navState.chatGPTResultSafe = nil
                    navState.assessmentResult = nil
                }
                .buttonStyle(SmallCyberBackButton(accentColor: accentColor, backgroundColor: secondaryBackgroundColor.opacity(0.3)))
                .padding(.top, 5)

                Spacer()
            }
            .navigationDestination(isPresented: $navState.isURLSubmitted) {
                QuestionnaireView(url: urlText, navState: navState)
                    .transition(.opacity)
                    .animation(.easeInOut(duration: 0.5), value: navState.isURLSubmitted)
                // Removed the redundant "Back to Home" button here as it's already in QuestionnaireView
            }
        }
        .navigationBarBackButtonHidden(true)
    }
}

// MARK: - Questionnaire View (URL Phishing Check)
struct QuestionnaireView: View {
    let url: String
    @ObservedObject var navState: NavigationState

    @State private var questions: [Question] = [
        Question(text: "Does the site have a lot of ads?"),
        Question(text: "Does the site have pop up ads?"),
        Question(text: "Does this site look unprofessional or unorganized?"),
        Question(text: "Does the site have a lot of download buttons?"),
        Question(text: "Did the site automatically download the application onto your device?"),
        Question(text: "Does the website have poor grammar?"),
        Question(text: "Are you downloading this in a bundle with other softwares?"),
        Question(text: "Does this seem too good to be true?")
    ]

    @State private var userText = ""
    @State private var isLoadingGeminiCheck = false

    let primaryBackgroundColor = Color(red: 0.08, green: 0.08, blue: 0.15)
    let secondaryBackgroundColor = Color(red: 0.12, green: 0.12, blue: 0.22)
    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let textColor = Color.white

    // Helper to determine if any answer is selected
    private var isAnyQuestionAnswered: Bool {
        questions.contains(where: { $0.answer != nil })
    }

    var body: some View {
        ZStack {
            primaryBackgroundColor // Apply primary background to the entire ZStack
                .ignoresSafeArea()

            VStack(spacing: 15) {
                Text("Questionnaire for")
                    .font(.system(size: 24, weight: .semibold, design: .rounded))
                    .foregroundColor(textColor)
                Text(url)
                    .font(.system(size: 16, weight: .medium, design: .rounded))
                    .foregroundColor(accentColor)
                    .multilineTextAlignment(.center)
                    .padding(.bottom, 5)

                ScrollView {
                    VStack(spacing: 15) {
                        ForEach($questions) { $question in
                            VStack(alignment: .leading) {
                                Text(question.text)
                                    .font(.system(size: 18, weight: .medium, design: .rounded))
                                    .foregroundColor(textColor)
                                Picker("Answer", selection: $question.answer) {
                                    Text("Yes").tag(QuestionAnswer.yes as QuestionAnswer?)
                                    Text("No").tag(QuestionAnswer.no as QuestionAnswer?)
                                    Text("Not Sure").tag(QuestionAnswer.notSure as QuestionAnswer?)
                                }
                                .pickerStyle(SegmentedPickerStyle())
                                .padding(.vertical, 5)
                                .background(secondaryBackgroundColor.opacity(0.6))
                                .cornerRadius(10)
                                .tint(accentColor)
                                .foregroundColor(textColor) // Ensure text color is visible
                            }
                        }

                        VStack(alignment: .leading, spacing: 5) {
                            Text("Optional: Describe anything unusual about this site")
                                .font(.system(size: 18, weight: .medium, design: .rounded))
                                .foregroundColor(textColor)

                            TextEditor(text: $userText)
                                .frame(height: 80)
                                .padding(5)
                                .background(secondaryBackgroundColor)
                                .cornerRadius(10)
                                .foregroundColor(textColor)
                                .accentColor(accentColor)
                                .opacity(0.8) // Increased opacity for better readability
                        }
                    }
                    .padding(.horizontal)
                    .padding(.bottom, 20) // Add padding at the bottom of the scrollable content
                }
                .background(primaryBackgroundColor) // Apply primary background to the ScrollView itself
                .scrollContentBackground(.hidden) // Hide default white background of ScrollView

                Button {
                    isLoadingGeminiCheck = true

                    Task {
                        await withCheckedContinuation { continuation in
                            callGeminiAPI(for: userText) { isGeminiAssessment in
                                navState.chatGPTResultSafe = isGeminiAssessment
                                continuation.resume()
                            }
                        }

                        isLoadingGeminiCheck = false

                        let localAIApproved = navState.isAIResultSafe ?? false
                        let geminiResult = navState.chatGPTResultSafe
                        let yesAnswersCount = questions.filter { $0.answer == .yes }.count

                        if localAIApproved && geminiResult == .safe && yesAnswersCount == 0 {
                            navState.assessmentResult = .safe
                        } else if !localAIApproved || geminiResult == .unsafe || yesAnswersCount >= 3 {
                            navState.assessmentResult = .unsafe
                        } else {
                            navState.assessmentResult = .suspicious
                        }

                        navState.isQuestionnaireSubmitted = true
                    }
                } label: {
                    if isLoadingGeminiCheck {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: textColor))
                            .padding(.vertical, 8)
                            .padding(.horizontal, 15)
                    } else {
                        Text(isAnyQuestionAnswered ? "Submit" : "Skip Questionnaire") // Conditional text
                            .font(.system(size: 20, weight: .bold, design: .rounded))
                            .padding(.vertical, 8)
                            .padding(.horizontal, 15)
                    }
                }
                .disabled(isLoadingGeminiCheck)
                .buttonStyle(CyberButtonStyle(accentColor: accentColor))
                .padding(.top, 5)
                .padding(.horizontal)

                Button("Back to URL Entry") {
                    navState.isURLSubmitted = false
                    navState.isAIResultSafe = nil
                    navState.skipAIURLCheck = false
                    navState.chatGPTResultSafe = nil
                    navState.assessmentResult = nil
                }
                .buttonStyle(SmallCyberBackButton(accentColor: accentColor, backgroundColor: secondaryBackgroundColor.opacity(0.3)))
                .padding(.top, 5)
                .padding(.bottom, 10)
            }
            .padding(15)
            .background(secondaryBackgroundColor, in: RoundedRectangle(cornerRadius: 25))
            .padding()
            .navigationDestination(isPresented: $navState.isQuestionnaireSubmitted) {
                ResultView(assessmentResult: navState.assessmentResult, navState: navState)
                    .transition(.opacity)
                    .animation(.easeInOut(duration: 0.5), value: navState.isQuestionnaireSubmitted)
            }
        }
        .navigationBarBackButtonHidden(true)
    }
}

// MARK: - Strong Password Maker View
struct PasswordMakerView: View {
    @ObservedObject var navState: NavigationState
    @State private var passwordLength: Double = 16
    @State private var includeUppercase: Bool = true
    @State private var includeLowercase: Bool = true
    @State private var includeNumbers: Bool = true
    @State private var includeSymbols: Bool = true
    @State private var generatedPassword: String = ""

    @State private var showCopiedMessage: Bool = false

    let primaryBackgroundColor = Color(red: 0.08, green: 0.08, blue: 0.15)
    let secondaryBackgroundColor = Color(red: 0.12, green: 0.12, blue: 0.22)
    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let textColor = Color.white

    var body: some View {
        ZStack {
            primaryBackgroundColor.ignoresSafeArea()

            VStack(spacing: 25) {
                Text("Strong Password Maker")
                    .font(.system(size: 30, weight: .bold, design: .rounded))
                    .foregroundColor(textColor)
                    .shadow(color: accentColor.opacity(0.6), radius: 8)
                    .padding(.bottom, 10)
                    .padding(.top, 50)

                // MARK: - Generated Password Display
                VStack(alignment: .leading, spacing: 10) {
                    Text("Generated Password:")
                        .font(.headline)
                        .foregroundColor(textColor.opacity(0.8))

                    Text(generatedPassword.isEmpty ? "Tap 'Generate' to create a password" : generatedPassword)
                        .font(.title2)
                        .fontWeight(.medium)
                        .foregroundColor(textColor)
                        .padding()
                        .frame(maxWidth: .infinity)
                        .background(secondaryBackgroundColor)
                        .cornerRadius(15)
                        .overlay(
                            RoundedRectangle(cornerRadius: 15)
                                .stroke(accentColor.opacity(0.7), lineWidth: 2)
                        )
                        .padding(.horizontal)
                        .multilineTextAlignment(.center)
                }

                // MARK: - Password Length Slider
                VStack(alignment: .leading) {
                    Text("Password Length: \(Int(passwordLength))")
                        .font(.subheadline)
                        .foregroundColor(textColor)

                    Slider(value: $passwordLength, in: 8...32, step: 1) {
                        Text("Length")
                    } minimumValueLabel: {
                        Text("8")
                    } maximumValueLabel: {
                        Text("32")
                    }
                    .tint(accentColor)
                }
                .padding(.horizontal)

                // MARK: - Character Type Toggles
                VStack(alignment: .leading, spacing: 15) {
                    Toggle(isOn: $includeUppercase) {
                        Text("Include Uppercase (A-Z)")
                    }
                    Toggle(isOn: $includeLowercase) {
                        Text("Include Lowercase (a-z)")
                    }
                    Toggle(isOn: $includeNumbers) {
                        Text("Include Numbers (0-9)")
                    }
                    Toggle(isOn: $includeSymbols) {
                        Text("Include Symbols (!@#$...)")
                    }
                }
                .font(.body)
                .foregroundColor(textColor)
                .toggleStyle(SwitchToggleStyle(tint: accentColor))
                .padding(.horizontal)

                // MARK: - Action Buttons
                HStack(spacing: 20) {
                    Button("Generate Password") {
                        generatePassword()
                    }
                    .buttonStyle(CyberButtonStyle(accentColor: accentColor))

                    Button("Copy") {
                        UIPasteboard.general.string = generatedPassword
                        showCopiedMessage = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                            showCopiedMessage = false
                        }
                    }
                    .buttonStyle(CyberButtonStyle(accentColor: accentColor))
                    .opacity(generatedPassword.isEmpty ? 0.5 : 1.0)
                    .disabled(generatedPassword.isEmpty)
                }

                // MARK: - Copied Message
                if showCopiedMessage {
                    Text("Copied to clipboard!")
                        .font(.caption)
                        .foregroundColor(.green)
                        .transition(.opacity)
                        .animation(.easeInOut, value: showCopiedMessage)
                }

                Spacer()

                Button("Back to Home") {
                    navState.showPasswordMaker = false
                }
                .buttonStyle(SmallCyberBackButton(accentColor: accentColor, backgroundColor: secondaryBackgroundColor.opacity(0.3)))
                .padding(.bottom, 20)
            }
            .padding(.vertical)
        }
        .onAppear {
            generatePassword()
        }
        .navigationBarBackButtonHidden(true)
    }

    // MARK: - Password Generation Logic
    private func generatePassword() {
        let uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        let lowercaseChars = "abcdefghijklmnopqrstuvwxyz"
        let numberChars = "0123456789"
        let symbolChars = "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~"

        var characterPool = ""
        if includeUppercase { characterPool += uppercaseChars }
        if includeLowercase { characterPool += lowercaseChars }
        if includeNumbers { characterPool += numberChars }
        if includeSymbols { characterPool += symbolChars }

        guard !characterPool.isEmpty else {
            generatedPassword = "Select at least one character type."
            return
        }

        var password = ""
        let passwordLengthInt = Int(passwordLength)

        var requiredChars: [Character] = []
        if includeUppercase, let char = uppercaseChars.randomElement() { requiredChars.append(char) }
        if includeLowercase, let char = lowercaseChars.randomElement() { requiredChars.append(char) }
        if includeNumbers, let char = numberChars.randomElement() { requiredChars.append(char) }
        if includeSymbols, let char = symbolChars.randomElement() { requiredChars.append(char) }

        // Ensure at least one of each selected type is included
        for char in requiredChars.shuffled() {
            if password.count < passwordLengthInt {
                password.append(char)
            }
        }

        // Fill the rest with random characters from the pool
        while password.count < passwordLengthInt {
            if let randomChar = characterPool.randomElement() {
                password.append(randomChar)
            }
        }

        // Shuffle the final password to mix the required characters
        generatedPassword = String(password.shuffled())
    }
}

// MARK: - Password Storage System
struct StoredPassword: Identifiable, Codable {
    let id: UUID
    var service: String
    var username: String
    var encryptedData: Data // This will store the AES.GCM.SealedBox.combined data
    var notes: String? // Made optional

    // Initializer for creating new or updating passwords
    init(id: UUID = UUID(), service: String, username: String, encryptedData: Data, notes: String?) {
        self.id = id
        self.service = service
        self.username = username
        self.encryptedData = encryptedData
        self.notes = notes
    }
}

// Helper extension for Data to generate random bytes (for salt)
extension Data {
    static func random(byteCount: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        _ = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
        return Data(bytes)
    }
}

class PasswordStorage: ObservableObject {
    @Published var passwords: [StoredPassword] = [] // Initialize here
    // Removed @AppStorage("biometricsEnabled") var biometricsEnabled: Bool = false

    private var masterPasswordHash: Data? // Stores the PBKDF2 derived key for master password
    private let masterPasswordHashKey = KeychainManager.masterPasswordAccount
    private let encryptionSaltKey = "com.YourApp.EncryptionSalt" // Salt for PBKDF2 of master password

    init() {
        self.masterPasswordHash = KeychainManager.load(key: masterPasswordHashKey)
        if self.masterPasswordHash != nil {
            print("PasswordStorage: Master password hash loaded from Keychain.")
        } else {
            print("PasswordStorage: No master password hash found in Keychain on launch.")
        }
        loadPasswords() // Now safe to call after properties are initialized
    }

    // MARK: - Master Password Management (with PBKDF2)

    func setMasterPassword(password: String) -> Bool {
        guard let passwordData = password.data(using: .utf8) else { return false }
        
        // Generate a new salt for PBKDF2 for the master password
        let salt = Data.random(byteCount: 16) // 16 bytes for salt is common
        UserDefaults.standard.set(salt, forKey: encryptionSaltKey)

        // Derive key using PBKDF2
        guard let derivedKey = Self.deriveKeyFromPassword(password: passwordData, salt: salt) else {
            print("Failed to derive key for master password.")
            return false
        }
        let newHash = Data(derivedKey) // PBKDF2 output is already a Data object

        let status = KeychainManager.save(key: masterPasswordHashKey, data: newHash)
        if status == errSecSuccess {
            self.masterPasswordHash = newHash // Update the in-memory hash
            print("Master password set successfully and saved to Keychain.")
            return true
        } else {
            print("Failed to save master password to Keychain: \(status)")
            return false
        }
    }

    func verifyMasterPassword(password: String) -> Bool {
        guard let storedHash = self.masterPasswordHash else {
            print("No master password hash found in memory to verify against.")
            // Try loading from Keychain one more time if not in memory (redundant if init works, but safe)
            self.masterPasswordHash = KeychainManager.load(key: masterPasswordHashKey)
            guard let reloadedHash = self.masterPasswordHash else {
                return false
            }
            return verifyDerivedKey(password: password, storedDerivedKey: reloadedHash)
        }
        return verifyDerivedKey(password: password, storedDerivedKey: storedHash)
    }

    private func verifyDerivedKey(password: String, storedDerivedKey: Data) -> Bool {
        guard let passwordData = password.data(using: .utf8) else { return false }
        guard let salt = UserDefaults.standard.data(forKey: encryptionSaltKey) else {
            print("Error: No salt found for master password verification.")
            return false
        }

        guard let inputDerivedKey = Self.deriveKeyFromPassword(password: passwordData, salt: salt) else {
            print("Failed to derive key for input password during verification.")
            return false
        }

        let matches = storedDerivedKey == inputDerivedKey
        if !matches {
            print("Master password verification failed.")
        }
        return matches
    }

    func hasMasterPassword() -> Bool {
        return self.masterPasswordHash != nil || KeychainManager.load(key: masterPasswordHashKey) != nil
    }

    func resetMasterPassword() {
        let status = KeychainManager.delete(key: masterPasswordHashKey)
        if status == errSecSuccess {
            self.masterPasswordHash = nil // Clear the in-memory hash
            print("Master password reset successfully.")
            // Clear all stored passwords as they were encrypted with a key derived from this master password
            self.passwords = []
            UserDefaults.standard.removeObject(forKey: "storedPasswords")
            UserDefaults.standard.removeObject(forKey: encryptionSaltKey) // Also remove the salt
        } else {
            print("Failed to delete master password from Keychain: \(status)")
        }
    }

    // MARK: - Password Data Storage (AES-GCM Encryption/Decryption)

    // Derives an encryption key from the master password's derived key using HKDF
    private func getEncryptionKey() throws -> SymmetricKey {
        guard let masterDerivedKeyData = self.masterPasswordHash else {
            throw PasswordStorageError.masterPasswordNotSet
        }
        guard let salt = UserDefaults.standard.data(forKey: encryptionSaltKey) else {
            throw PasswordStorageError.encryptionSaltMissing
        }

        // Use HKDF to derive a strong symmetric key for AES-256
        let symmetricKey = SymmetricKey(data: masterDerivedKeyData)
        let derivedEncryptionKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: symmetricKey,
            salt: salt, // Re-use the master password salt for consistency in key derivation
            outputByteCount: 32 // For AES-256
        )
        return derivedEncryptionKey
    }

    private func savePasswords() {
        guard !passwords.isEmpty else {
            UserDefaults.standard.removeObject(forKey: "storedPasswords")
            print("No passwords to save, cleared storedPasswords.")
            return
        }

        do {
            let encoded = try JSONEncoder().encode(passwords)
            UserDefaults.standard.set(encoded, forKey: "storedPasswords")
            print("Passwords saved to UserDefaults (now encrypted).")
        } catch {
            print("Error encoding passwords for saving: \(error)")
        }
    }

    private func loadPasswords() {
        guard let savedPasswordsData = UserDefaults.standard.data(forKey: "storedPasswords") else {
            self.passwords = []
            return
        }
        do {
            self.passwords = try JSONDecoder().decode([StoredPassword].self, from: savedPasswordsData)
            print("Passwords loaded from UserDefaults.")
        } catch {
            print("Error decoding passwords for loading: \(error)")
            self.passwords = [] // Clear if unable to decode
        }
    }

    func encryptPassword(plaintext: String) -> Data? {
        guard let plaintextData = plaintext.data(using: .utf8) else { return nil }
        do {
            let key = try getEncryptionKey()
            let sealedBox = try AES.GCM.seal(plaintextData, using: key)
            return sealedBox.combined // combined contains nonce, ciphertext, and tag
        } catch {
            print("Encryption failed: \(error)")
            return nil
        }
    }

    func decryptPassword(encryptedData: Data) -> String? {
        do {
            let key = try getEncryptionKey()
            let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
            let decryptedData = try AES.GCM.open(sealedBox, using: key)
            return String(data: decryptedData, encoding: .utf8)
        } catch {
            print("Decryption failed: \(error)")
            return nil
        }
    }

    func getDecryptedPassword(for storedPassword: StoredPassword) -> String {
        // encryptedData is non-optional, so no need for conditional binding or nil coalescing
        if let decrypted = decryptPassword(encryptedData: storedPassword.encryptedData) {
            return decrypted
        }
        return "****** DECRYPTION FAILED ******"
    }

    func addPassword(service: String, username: String, passwordText: String, notes: String?) {
        guard let encryptedData = encryptPassword(plaintext: passwordText) else {
            print("Failed to encrypt password for adding.")
            return
        }

        let newPassword = StoredPassword(
            service: service,
            username: username,
            encryptedData: encryptedData,
            notes: notes
        )
        passwords.append(newPassword)
    }

    func updatePassword(id: UUID, service: String, username: String, passwordText: String, notes: String?) {
        if let index = passwords.firstIndex(where: { $0.id == id }) {
            guard let encryptedData = encryptPassword(plaintext: passwordText) else {
                print("Failed to encrypt password for updating.")
                return
            }

            passwords[index] = StoredPassword(id: id, service: service, username: username, encryptedData: encryptedData, notes: notes)
        }
    }

    func deletePassword(at offsets: IndexSet) {
        passwords.remove(atOffsets: offsets)
    }

    // MARK: - PBKDF2 Key Derivation for Master Password (using CommonCrypto)
    // This is used to hash the master password securely.
    static func deriveKeyFromPassword(password: Data, salt: Data) -> Data? {
        let iterations = 100_000 // High iteration count for security
        let keyLength = kCCKeySizeAES256 // 32 bytes for SHA256 output

        var derivedKey = Data(count: keyLength)
        let status = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
            password.withUnsafeBytes { passwordBytes in
                salt.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.baseAddress, passwordBytes.count,
                        saltBytes.baseAddress, saltBytes.count,
                        .init(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        derivedKeyBytes.baseAddress, keyLength
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            print("PBKDF2 key derivation failed: \(status)")
            return nil
        }
        return derivedKey
    }

    enum PasswordStorageError: Error {
        case masterPasswordNotSet
        case encryptionSaltMissing
        case encryptionFailed
        case decryptionFailed
    }
}

// MARK: - TwoFactorAuthView
struct TwoFactorAuthView: View {
    @Binding var isAuthenticated: Bool
    @State private var passwordInput: String = ""
    @State private var showingAlert = false
    @State private var alertMessage = ""
    @EnvironmentObject var passwordStorage: PasswordStorage
    @EnvironmentObject var navState: NavigationState
    @State private var showingResetConfirmation = false // New state for reset confirmation

    let primaryBackgroundColor = Color(red: 0.08, green: 0.08, blue: 0.15)
    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let secondaryBackgroundColor = Color(red: 0.12, green: 0.12, blue: 0.22)

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "lock.shield.fill")
                .resizable()
                .frame(width: 100, height: 100)
                .foregroundColor(accentColor)
            Text("Unlock Password Storage")
                .font(.title)
                .fontWeight(.bold)
                .foregroundColor(.white)

            if passwordStorage.hasMasterPassword() {
                SecureField("Master Password", text: $passwordInput)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .padding()
                    .background(Color.white.opacity(0.1))
                    .cornerRadius(10)
                    .foregroundColor(.white)
                    .accentColor(accentColor)

                Button("Unlock with Password") {
                    if passwordStorage.verifyMasterPassword(password: passwordInput) {
                        isAuthenticated = true
                    } else {
                        alertMessage = "Incorrect password. Please try again."
                        showingAlert = true
                    }
                }
                .buttonStyle(CyberButtonStyle(accentColor: accentColor))
                .padding(.horizontal)
                
                // Removed Biometric Unlock button
                
                // NEW: Forgot Master Password Button
                Button("Forgot Master Password?") {
                    showingResetConfirmation = true
                }
                .buttonStyle(SmallCyberBackButton(accentColor: .red, backgroundColor: secondaryBackgroundColor.opacity(0.3)))
                .padding(.horizontal)

            } else {
                Text("Set up your Master Password first!")
                    .font(.headline)
                    .foregroundColor(.orange)
                    .multilineTextAlignment(.center)
                    .padding()
            }
            Spacer()

            Button("Back to Home") {
                navState.showPasswordStorage = false
            }
            .buttonStyle(SmallCyberBackButton(accentColor: accentColor, backgroundColor: secondaryBackgroundColor.opacity(0.3)))
            .padding(.bottom, 20)
        }
        .padding()
        .background(primaryBackgroundColor.ignoresSafeArea())
        .alert("Authentication Failed", isPresented: $showingAlert) {
            Button("OK") { }
        } message: {
            Text(alertMessage)
        }
        .alert("Reset Master Password", isPresented: $showingResetConfirmation) {
            Button("Reset", role: .destructive) {
                passwordStorage.resetMasterPassword()
                isAuthenticated = false // Go back to auth screen
                // This will trigger the SetMasterPasswordView flow
                // since hasMasterPassword() will now return false
            }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("This will delete your current master password and ALL stored passwords. You will need to set up a new master password. Are you sure?")
        }
        .onAppear {
            // Removed biometric authentication attempt on appear
        }
    }
    // Removed authenticateBiometrics() function
}

// MARK: - PasswordStorageView (Main Password List)
struct PasswordStorageView: View {
    @ObservedObject var navState: NavigationState
    @EnvironmentObject var passwordStorage: PasswordStorage
    @State private var showingAddEditSheet = false
    @State private var selectedPassword: StoredPassword? = nil
    @State private var isUnlocked = false // Renamed from showingAuth and initialized to false
    @State private var masterPasswordSetup = false // State for initial setup

    let primaryBackgroundColor = Color(red: 0.08, green: 0.08, blue: 0.15)
    let secondaryBackgroundColor = Color(red: 0.12, green: 0.12, blue: 0.22)
    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let textColor = Color.white

    var body: some View {
        ZStack {
            primaryBackgroundColor.ignoresSafeArea()

            VStack {
                if !passwordStorage.hasMasterPassword() { // Check if master password exists first
                    SetMasterPasswordView(masterPasswordSetup: $masterPasswordSetup, isParentUnlocked: $isUnlocked) // Pass isUnlocked
                        .environmentObject(passwordStorage)
                        .environmentObject(navState)
                } else if !isUnlocked { // If master password exists but not unlocked
                    TwoFactorAuthView(isAuthenticated: $isUnlocked)
                        .environmentObject(passwordStorage)
                        .environmentObject(navState)
                } else {
                    // This block will only show when isUnlocked is true and a master password is set (or was just set)
                    List {
                        // Removed Biometric Unlock Toggle
                        ForEach(passwordStorage.passwords) { pwd in
                            VStack(alignment: .leading, spacing: 5) {
                                Text(pwd.service)
                                    .font(.headline)
                                    .foregroundColor(accentColor)
                                Text("Username: \(pwd.username)")
                                    .font(.subheadline)
                                    .foregroundColor(textColor.opacity(0.9))
                                HStack {
                                    Text("Password: \(passwordStorage.getDecryptedPassword(for: pwd))")
                                        .font(.subheadline)
                                        .foregroundColor(textColor.opacity(0.8))
                                    Button {
                                        UIPasteboard.general.string = passwordStorage.getDecryptedPassword(for: pwd)
                                    } label: {
                                        Image(systemName: "doc.on.doc")
                                            .foregroundColor(accentColor)
                                    }
                                }
                                if let notes = pwd.notes, !notes.isEmpty {
                                    Text("Notes: \(notes)")
                                        .font(.caption)
                                        .foregroundColor(textColor.opacity(0.7))
                                }
                            }
                            .padding(.vertical, 5)
                            .listRowBackground(secondaryBackgroundColor)
                            .onTapGesture {
                                selectedPassword = pwd
                                showingAddEditSheet = true
                            }
                        }
                        .onDelete(perform: passwordStorage.deletePassword)
                    }
                    .listStyle(.plain)
                    .background(primaryBackgroundColor)
                    .scrollContentBackground(.hidden)

                    Button("Add New Password") {
                        selectedPassword = nil
                        showingAddEditSheet = true
                    }
                    .buttonStyle(CyberButtonStyle(accentColor: accentColor))
                    .padding()

                    Button("Back to Home") {
                        navState.showPasswordStorage = false
                        isUnlocked = false // Reset unlock state when leaving
                    }
                    .buttonStyle(SmallCyberBackButton(accentColor: accentColor, backgroundColor: secondaryBackgroundColor.opacity(0.3)))
                    .padding(.bottom, 20)

                    #if DEBUG // This button only appears in debug builds
                    Button("DEBUG: Reset Master Password & All Data") {
                        passwordStorage.resetMasterPassword()
                        isUnlocked = false // Go back to auth screen after reset
                        masterPasswordSetup = false // Ensure setup flow is triggered again
                    }
                    .buttonStyle(SmallCyberBackButton(accentColor: .red, backgroundColor: secondaryBackgroundColor.opacity(0.3)))
                    .padding(.bottom, 10)
                    #endif
                }
            }
            .sheet(isPresented: $showingAddEditSheet) {
                AddEditPasswordView(password: $selectedPassword)
                    .environmentObject(passwordStorage)
            }
            .onAppear {
                // Initialize `isUnlocked` based on whether a master password exists
                // If a master password exists, always start with the auth screen (so isUnlocked is false initially).
                // If not, go straight to setup (so isUnlocked is false, and the !hasMasterPassword() branch is taken).
                if passwordStorage.hasMasterPassword() {
                    isUnlocked = false // Start locked if master password exists
                } else {
                    isUnlocked = false // Still locked, but will go to setup
                    masterPasswordSetup = false // Ensure setup flow is triggered if no master password
                }
            }
            .navigationBarBackButtonHidden(true)
        }
    }
}

// MARK: - SetMasterPasswordView
struct SetMasterPasswordView: View {
    @EnvironmentObject var passwordStorage: PasswordStorage
    @Binding var masterPasswordSetup: Bool
    @Binding var isParentUnlocked: Bool // New binding to control parent's unlocked state
    @State private var newPassword = ""
    @State private var confirmPassword = ""
    @State private var showingAlert = false
    @State private var alertMessage = ""
    @EnvironmentObject var navState: NavigationState

    let primaryBackgroundColor = Color(red: 0.08, green: 0.08, blue: 0.15)
    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let secondaryBackgroundColor = Color(red: 0.12, green: 0.12, blue: 0.22)

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Text("Set Master Password")
                .font(.title)
                .fontWeight(.bold)
                .foregroundColor(.white)
            Text("This password will protect your stored passwords. Don't forget it!")
                .font(.subheadline)
                .foregroundColor(.white.opacity(0.8))
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            SecureField("New Master Password", text: $newPassword)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()
                .background(Color.white.opacity(0.1))
                .cornerRadius(10)
                .foregroundColor(.white)
                .accentColor(accentColor)

            SecureField("Confirm Master Password", text: $confirmPassword)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()
                .background(Color.white.opacity(0.1))
                .cornerRadius(10)
                .foregroundColor(.white)
                .accentColor(accentColor)

            Button("Set Password") {
                if newPassword.isEmpty || confirmPassword.isEmpty {
                    alertMessage = "Please enter and confirm your new password."
                    showingAlert = true
                } else if newPassword != confirmPassword {
                    alertMessage = "Passwords do not match."
                    showingAlert = true
                } else {
                    if passwordStorage.setMasterPassword(password: newPassword) {
                        masterPasswordSetup = true // Mark as set up
                        isParentUnlocked = true // Directly unlock the parent view
                    } else {
                        alertMessage = "Failed to set master password. Please try again."
                        showingAlert = true
                    }
                }
            }
            .buttonStyle(CyberButtonStyle(accentColor: .green))
            .padding(.horizontal)
            Spacer()

            Button("Back to Home") {
                navState.showPasswordStorage = false
            }
            .buttonStyle(SmallCyberBackButton(accentColor: accentColor, backgroundColor: secondaryBackgroundColor.opacity(0.3)))
            .padding(.bottom, 20)
        }
        .padding()
        .background(primaryBackgroundColor.ignoresSafeArea())
        .alert("Error", isPresented: $showingAlert) {
            Button("OK") { }
        } message: {
            Text(alertMessage)
        }
    }
}

// MARK: - AddEditPasswordView
struct AddEditPasswordView: View {
    @Environment(\.dismiss) var dismiss
    @EnvironmentObject var passwordStorage: PasswordStorage
    @Binding var password: StoredPassword? // Nil for Add, has value for Edit
    
    @State private var service: String = ""
    @State private var username: String = ""
    @State private var plaintextPassword: String = "" // This will be encrypted before saving
    @State private var notes: String = ""
    
    let primaryBackgroundColor = Color(red: 0.08, green: 0.08, blue: 0.15)
    let secondaryBackgroundColor = Color(red: 0.12, green: 0.12, blue: 0.22)
    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let textColor = Color.white
    
    var body: some View {
        NavigationView {
            Form {
                passwordDetailsSection
                actionButton
            }
            .scrollContentBackground(.hidden)
            .background(primaryBackgroundColor)
            .navigationTitle(password == nil ? "Add Password" : "Edit Password")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        dismiss()
                    }
                    .foregroundColor(accentColor)
                }
            }
            .onAppear {
                if let pwd = password {
                    service = pwd.service
                    username = pwd.username
                    plaintextPassword = passwordStorage.getDecryptedPassword(for: pwd) // Decrypt for editing
                    notes = pwd.notes ?? "" // Handle optional notes
                }
            }
        }
    }
    
    // MARK: - Extracted View Components
    
    private var passwordDetailsSection: some View {
        Section(header: Text("Password Details").foregroundColor(accentColor)) {
            TextField("Service (e.g., Google, Facebook)", text: $service)
                .listRowBackground(secondaryBackgroundColor)
                .foregroundColor(textColor)
                .accentColor(accentColor)
            
            TextField("Username/Email", text: $username)
                .listRowBackground(secondaryBackgroundColor)
                .foregroundColor(textColor)
                .accentColor(accentColor)
            
            SecureField("Password", text: $plaintextPassword)
                .listRowBackground(secondaryBackgroundColor)
                .foregroundColor(textColor)
                .accentColor(accentColor)
            
            TextField("Notes (optional)", text: $notes, axis: .vertical)
                .listRowBackground(secondaryBackgroundColor)
                .foregroundColor(textColor)
                .accentColor(accentColor)
        }
        .textInputAutocapitalization(.never)
        .autocorrectionDisabled()
    }
    
    private var actionButton: some View {
        Button(password == nil ? "Add Password" : "Save Changes") {
            if password == nil {
                passwordStorage.addPassword(service: service, username: username, passwordText: plaintextPassword, notes: notes)
            } else if let id = password?.id {
                passwordStorage.updatePassword(id: id, service: service, username: username, passwordText: plaintextPassword, notes: notes)
            }
            dismiss()
        }
        .buttonStyle(CyberButtonStyle(accentColor: accentColor))
        .listRowBackground(Color.clear)
    }
}

// MARK: - Mini Quiz Feature
struct QuizQuestion: Identifiable {
    let id = UUID()
    let text: String
    let options: [String]
    let correctAnswerIndex: Int
    var selectedAnswerIndex: Int?
}

struct MiniQuizView: View {
    @ObservedObject var navState: NavigationState
    @State private var questions: [QuizQuestion] = [
        QuizQuestion(text: "What is phishing?", options: ["A type of online game", "A technique to trick you into revealing personal information", "A new kind of fish", "A social media platform"], correctAnswerIndex: 1),
        QuizQuestion(text: "What does 'HTTPS' in a URL indicate?", options: ["It's a very fast website", "The website is secure and encrypted", "It's a shopping website", "It's an outdated protocol"], correctAnswerIndex: 1),
        QuizQuestion(text: "Which of these is a sign of a suspicious email?", options: ["Perfect grammar", "A generic greeting (e.g., 'Dear Customer')", "It's from a known sender", "It contains a link to a major news site"], correctAnswerIndex: 1),
        QuizQuestion(text: "Why is it important to use strong, unique passwords?", options: ["They are easy to remember", "They protect against unauthorized access", "They make your computer run faster", "They are required by most websites"], correctAnswerIndex: 1),
        QuizQuestion(text: "What is Two-Factor Authentication (2FA)?", options: ["Logging in with two different usernames", "Using a password and a second verification method (e.g., code from phone)", "Sharing your password with two friends", "A method for faster internet connection"], correctAnswerIndex: 1)
    ]
    @State private var showResults = false
    @State private var score = 0

    let primaryBackgroundColor = Color(red: 0.08, green: 0.08, blue: 0.15)
    let secondaryBackgroundColor = Color(red: 0.12, green: 0.12, blue: 0.22)
    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let textColor = Color.white

    var body: some View {
        ZStack {
            primaryBackgroundColor.ignoresSafeArea()

            VStack(spacing: 20) {
                Text("Cybersecurity Mini Quiz")
                    .font(.system(size: 30, weight: .bold, design: .rounded))
                    .foregroundColor(textColor)
                    .shadow(color: accentColor.opacity(0.6), radius: 8)
                    .padding(.bottom, 10)
                    .padding(.top, 50)

                if showResults {
                    QuizResultView(score: score, totalQuestions: questions.count, navState: navState)
                } else {
                    ScrollView {
                        VStack(spacing: 25) {
                            ForEach(questions.indices, id: \.self) { index in
                                VStack(alignment: .leading, spacing: 10) {
                                    Text("Question \(index + 1): \(questions[index].text)")
                                        .font(.headline)
                                        .foregroundColor(textColor)

                                    ForEach(questions[index].options.indices, id: \.self) { optionIndex in
                                        Button {
                                            questions[index].selectedAnswerIndex = optionIndex
                                        } label: {
                                            HStack {
                                                Image(systemName: questions[index].selectedAnswerIndex == optionIndex ? "largecircle.fill.circle" : "circle")
                                                    .foregroundColor(accentColor)
                                                Text(questions[index].options[optionIndex])
                                                    .foregroundColor(textColor)
                                                Spacer()
                                            }
                                            .padding(.vertical, 8)
                                            .padding(.horizontal)
                                            .background(
                                                RoundedRectangle(cornerRadius: 10)
                                                    .fill(secondaryBackgroundColor.opacity(0.7))
                                            )
                                        }
                                    }
                                }
                                .padding(.horizontal)
                            }
                        }
                        .padding(.bottom, 20) // Add padding at the bottom of the scrollable content
                    }
                    .background(primaryBackgroundColor) // Apply primary background to the ScrollView itself
                    .scrollContentBackground(.hidden) // Hide default scroll view background

                    Button("Submit Quiz") {
                        calculateScore()
                        showResults = true
                    }
                    .buttonStyle(CyberButtonStyle(accentColor: accentColor))
                    .disabled(!allQuestionsAnswered)
                    .padding(.horizontal)
                    .padding(.top, 20)
                }

                Button("Back to Home") {
                    navState.showMiniQuiz = false
                    resetQuiz()
                }
                .buttonStyle(SmallCyberBackButton(accentColor: accentColor, backgroundColor: secondaryBackgroundColor.opacity(0.3)))
                .padding(.bottom, 20)
            }
        }
        .navigationBarBackButtonHidden(true)
    }

    private var allQuestionsAnswered: Bool {
        questions.allSatisfy { $0.selectedAnswerIndex != nil }
    }

    private func calculateScore() {
        score = 0
        for question in questions {
            if question.selectedAnswerIndex == question.correctAnswerIndex {
                score += 1
            }
        }
    }

    private func resetQuiz() {
        for i in questions.indices {
            questions[i].selectedAnswerIndex = nil
        }
        score = 0
        showResults = false
    }
}

// MARK: - QuizResultView
struct QuizResultView: View {
    let score: Int
    let totalQuestions: Int
    @ObservedObject var navState: NavigationState

    let primaryBackgroundColor = Color(red: 0.08, green: 0.08, blue: 0.15)
    let secondaryBackgroundColor = Color(red: 0.12, green: 0.12, blue: 0.22)
    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let textColor = Color.white

    var assessmentResult: AssessmentResult {
        let percentage = Double(score) / Double(totalQuestions)
        if percentage >= 0.8 {
            return .safe
        } else if percentage >= 0.5 {
            return .suspicious
        } else {
            return .unsafe
        }
    }

    var body: some View {
        VStack(spacing: 25) {
            Text("Quiz Results")
                .font(.largeTitle)
                .fontWeight(.bold)
                .foregroundColor(textColor)

            Text("You scored \(score) out of \(totalQuestions)!")
                .font(.title2)
                .foregroundColor(textColor.opacity(0.9))

            Image(systemName: resultIcon)
                .resizable()
                .frame(width: 80, height: 80)
                .foregroundColor(resultColor)

            Text(LearnMoreText(for: assessmentResult, type: .general))
                .font(.body)
                .foregroundColor(textColor.opacity(0.8))
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            Button("Retake Quiz") {
                navState.showMiniQuiz = false // Go back to the quiz start
                // The quiz state will be reset when MiniQuizView is re-initialized
            }
            .buttonStyle(CyberButtonStyle(accentColor: accentColor))
        }
        .padding()
        .background(secondaryBackgroundColor)
        .cornerRadius(20)
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity) // Ensure it takes full space
        .background(primaryBackgroundColor.ignoresSafeArea()) // Apply background to cover all
    }

    var resultIcon: String {
        switch assessmentResult {
        case .safe: return "lightbulb.fill"
        case .unsafe: return "exclamationmark.bubble.fill"
        case .suspicious: return "questionmark.bubble.fill"
        }
    }

    var resultColor: Color {
        switch assessmentResult {
        case .safe: return .green
        case .unsafe: return .red
        case .suspicious: return .orange
        }
    }
}

// MARK: - Gemini AI Chat View
struct GeminiChatView: View {
    @ObservedObject var navState: NavigationState
    @State private var messageText: String = ""
    @State private var chatHistory: [[String: String]] = [] // "role": "user" or "model", "text": "message"
    @State private var isLoadingResponse = false

    let primaryBackgroundColor = Color(red: 0.08, green: 0.08, blue: 0.15)
    let secondaryBackgroundColor = Color(red: 0.12, green: 0.12, blue: 0.22)
    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let textColor = Color.white

    var body: some View {
        ZStack {
            primaryBackgroundColor.ignoresSafeArea()

            VStack(spacing: 0) {
                Text("Chat with Cyber-AI")
                    .font(.system(size: 30, weight: .bold, design: .rounded))
                    .foregroundColor(textColor)
                    .shadow(color: accentColor.opacity(0.6), radius: 8)
                    .padding(.bottom, 10)
                    .padding(.top, 50)

                ScrollView {
                    VStack(alignment: .leading, spacing: 15) {
                        ForEach(chatHistory, id: \.self.debugDescription) { message in // Using debugDescription for unique ID
                            ChatBubble(text: message["text"] ?? "", isUser: message["role"] == "user")
                        }
                        if isLoadingResponse {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: accentColor))
                                .padding(.horizontal)
                        }
                    }
                    .padding()
                    .frame(maxWidth: .infinity) // Ensures the chat bubbles container expands
                }
                .background(secondaryBackgroundColor.opacity(0.7))
                .cornerRadius(15)
                .padding(.horizontal)

                HStack {
                    TextField("Ask about a situation...", text: $messageText, axis: .vertical)
                        .padding(.vertical, 10)
                        .padding(.horizontal)
                        .background(secondaryBackgroundColor)
                        .cornerRadius(10)
                        .foregroundColor(textColor)
                        .accentColor(accentColor)
                        .font(.system(size: 16, design: .rounded))
                        .overlay(
                            RoundedRectangle(cornerRadius: 10)
                                .stroke(accentColor, lineWidth: 1)
                        )
                        .frame(minHeight: 40)
                        .frame(maxWidth: .infinity) // Ensures the TextField expands to fill available width

                    Button {
                        sendMessage()
                    } label: {
                        Image(systemName: "paperplane.fill")
                            .font(.title2)
                            .padding(8)
                            .background(accentColor)
                            .foregroundColor(.white)
                            .cornerRadius(10)
                    }
                    .disabled(messageText.isEmpty || isLoadingResponse)
                }
                .padding()

                Button("Back to Home") {
                    navState.showGeminiChat = false
                    chatHistory = [] // Clear chat when leaving
                    messageText = ""
                }
                .buttonStyle(SmallCyberBackButton(accentColor: accentColor, backgroundColor: secondaryBackgroundColor.opacity(0.3)))
                .padding(.bottom, 20)
            }
        }
        .navigationBarBackButtonHidden(true)
    }

    private func sendMessage() {
        let userMessage = messageText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !userMessage.isEmpty else { return }

        chatHistory.append(["role": "user", "text": userMessage])
        isLoadingResponse = true
        messageText = "" // Clear input field

        // Prepare history for Gemini API call
        var apiHistory: [[String: String]] = []
        for msg in chatHistory {
            // Only include user messages and model responses in the history sent to Gemini
            if msg["role"] == "user" {
                apiHistory.append(["role": "user", "text": msg["text"]!])
            } else if msg["role"] == "model" {
                apiHistory.append(["role": "model", "text": msg["text"]!])
            }
        }

        callGeminiChatAPI(for: userMessage, history: apiHistory) { response, assessmentResult in
            isLoadingResponse = false
            if let response = response {
                chatHistory.append(["role": "model", "text": response])
            } else {
                chatHistory.append(["role": "model", "text": "I'm sorry, I couldn't process that. Please try again."])
            }
        }
    }
}

struct ChatBubble: View {
    let text: String
    let isUser: Bool

    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let textColor = Color.white

    var body: some View {
        HStack {
            if isUser {
                Spacer()
            }
            Text(text)
                .padding(10)
                .background(isUser ? accentColor : Color.gray.opacity(0.3))
                .foregroundColor(textColor)
                .cornerRadius(15) // Corrected this line
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 250, alignment: isUser ? .trailing : .leading)
            if !isUser {
                Spacer()
            }
        }
    }
}

// MARK: - Home Screen
struct HomeView: View {
    @StateObject private var navState = NavigationState()
    @StateObject private var passwordStorage = PasswordStorage() // EnvironmentObject for Password Storage

    let primaryBackgroundColor = Color(red: 0.08, green: 0.08, blue: 0.15)
    let secondaryBackgroundColor = Color(red: 0.12, green: 0.12, blue: 0.22)
    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let textColor = Color.white

    var body: some View {
        NavigationStack {
            ZStack {
                primaryBackgroundColor
                    .ignoresSafeArea()

                VStack(spacing: 30) {
                    Spacer()

                    Text("Cyber-Check")
                        .font(.system(size: 44, weight: .bold, design: .rounded))
                        .foregroundColor(accentColor)
                        .shadow(color: accentColor.opacity(0.7), radius: 15)
                        .padding(.bottom, 20)

                    VStack(spacing: 20) {
                        Button("Check URL Safety") {
                            // Reset relevant states
                            navState.isURLSubmitted = false
                            navState.isQuestionnaireSubmitted = false
                            navState.isAIResultSafe = nil
                            navState.chatGPTResultSafe = nil
                            navState.skipAIURLCheck = false
                            navState.assessmentResult = nil
                            // Navigate to URL Check
                            navState.showURLCheck = true
                            navState.showEmailCheck = false
                            navState.showPasswordMaker = false
                            navState.showPasswordStorage = false
                            navState.showMiniQuiz = false
                            navState.showGeminiChat = false
                        }
                        .buttonStyle(CyberButtonStyle(accentColor: accentColor))

                        Button("Check Email Safety") {
                            // Reset relevant states
                            navState.isURLSubmitted = false
                            navState.isQuestionnaireSubmitted = false
                            navState.isAIResultSafe = nil
                            navState.chatGPTResultSafe = nil
                            navState.skipAIURLCheck = false
                            navState.assessmentResult = nil
                            // Navigate to Email Check
                            navState.showURLCheck = false
                            navState.showPasswordMaker = false
                            navState.showPasswordStorage = false
                            navState.showMiniQuiz = false
                            navState.showGeminiChat = false
                            navState.showEmailCheck = true
                        }
                        .buttonStyle(CyberButtonStyle(accentColor: accentColor))

                        Button("Strong Password Maker") {
                            // Reset relevant states
                            navState.isURLSubmitted = false
                            navState.isQuestionnaireSubmitted = false
                            navState.isAIResultSafe = nil
                            navState.chatGPTResultSafe = nil
                            navState.skipAIURLCheck = false
                            navState.assessmentResult = nil
                            // Navigate to Password Maker
                            navState.showURLCheck = false
                            navState.showEmailCheck = false
                            navState.showPasswordStorage = false
                            navState.showMiniQuiz = false
                            navState.showGeminiChat = false
                            navState.showPasswordMaker = true
                        }
                        .buttonStyle(CyberButtonStyle(accentColor: accentColor))

                        // NEW: Password Storage Button
                        Button("Secure Password Storage") {
                            navState.isURLSubmitted = false
                            navState.isQuestionnaireSubmitted = false
                            navState.isAIResultSafe = nil
                            navState.chatGPTResultSafe = nil
                            navState.skipAIURLCheck = false
                            navState.assessmentResult = nil
                            navState.showURLCheck = false
                            navState.showEmailCheck = false
                            navState.showPasswordMaker = false
                            navState.showMiniQuiz = false
                            navState.showGeminiChat = false
                            navState.showPasswordStorage = true
                        }
                        .buttonStyle(CyberButtonStyle(accentColor: accentColor))

                        // NEW: Mini Quiz Button
                        Button("Cyber-Safety Mini Quiz") {
                            navState.isURLSubmitted = false
                            navState.isQuestionnaireSubmitted = false
                            navState.isAIResultSafe = nil
                            navState.chatGPTResultSafe = nil
                            navState.skipAIURLCheck = false
                            navState.assessmentResult = nil
                            navState.showURLCheck = false
                            navState.showEmailCheck = false
                            navState.showPasswordMaker = false
                            navState.showPasswordStorage = false
                            navState.showGeminiChat = false
                            navState.showMiniQuiz = true
                        }
                        .buttonStyle(CyberButtonStyle(accentColor: accentColor))

                        // NEW: Gemini AI Chat Button
                        Button("Chat with Cyber-AI") {
                            navState.isURLSubmitted = false
                            navState.isQuestionnaireSubmitted = false
                            navState.isAIResultSafe = nil
                            navState.chatGPTResultSafe = nil
                            navState.skipAIURLCheck = false
                            navState.assessmentResult = nil
                            navState.showURLCheck = false
                            navState.showEmailCheck = false
                            navState.showPasswordMaker = false
                            navState.showPasswordStorage = false
                            navState.showMiniQuiz = false
                            navState.showGeminiChat = true
                        }
                        .buttonStyle(CyberButtonStyle(accentColor: accentColor))
                    }
                    .padding(.horizontal)

                    // MARK: - Disclaimer Section
                    Text("")
                    //Disclaimer: Cyber-Check is an AI-powered tool designed to assist in identifying potential online threats in URLs and emails, and to help generate strong passwords. It also includes educational resources like a cybersecurity quiz and an AI chat for general safety information. While we strive for accuracy, this app is for informational and educational purposes only and should not be considered a substitute for professional cybersecurity advice or comprehensive security solutions. Always exercise your own judgment, verify information from multiple trusted sources, and practice safe online habits. Your data security, especially for stored passwords, relies on your master password and device security. We are not responsible for any direct or indirect damages or losses resulting from the use of this application.
                        .font(.caption)
                        .foregroundColor(textColor.opacity(0.7))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                        .padding(.bottom, 10)

                    Spacer()
                }
                .navigationDestination(isPresented: $navState.showURLCheck) {
                    ContentView(navState: navState)
                        .transition(.opacity)
                        .animation(.easeInOut(duration: 0.5), value: navState.showURLCheck)
                }
                .navigationDestination(isPresented: $navState.showEmailCheck) {
                    EmailCheckView(navState: navState)
                        .transition(.opacity)
                        .animation(.easeInOut(duration: 0.5), value: navState.showEmailCheck)
                }
                .navigationDestination(isPresented: $navState.showPasswordMaker) {
                    PasswordMakerView(navState: navState)
                        .transition(.opacity)
                        .animation(.easeInOut(duration: 0.5), value: navState.showPasswordMaker)
                }
                .navigationDestination(isPresented: $navState.showPasswordStorage) {
                    PasswordStorageView(navState: navState)
                        .environmentObject(passwordStorage) // Pass environment object
                        .transition(.opacity)
                        .animation(.easeInOut(duration: 0.5), value: navState.showPasswordStorage)
                }
                .navigationDestination(isPresented: $navState.showMiniQuiz) {
                    MiniQuizView(navState: navState)
                        .transition(.opacity)
                        .animation(.easeInOut(duration: 0.5), value: navState.showMiniQuiz)
                }
                .navigationDestination(isPresented: $navState.showGeminiChat) {
                    GeminiChatView(navState: navState)
                        .transition(.opacity)
                        .animation(.easeInOut(duration: 0.5), value: navState.showGeminiChat)
                }
            }
        }
    }
}

// MARK: - App Entry Point
@main
struct URLQuestionnaireApp: App {
    var body: some Scene {
        WindowGroup {
            HomeView()
        }
    }
}
