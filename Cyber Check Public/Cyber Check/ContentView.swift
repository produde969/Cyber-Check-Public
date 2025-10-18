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
    @Published var isAIResultSafe: Bool? = nil                 // legacy flag used by some screens
    @Published var modelAssessment: AssessmentResult? = nil    // model-first result
    @Published var chatGPTResultSafe: AssessmentResult? = nil  // gemini result for URL/email text checks
    @Published var skipAIURLCheck = false                      // if true, we skip Gemini for URL flow (e.g., HTTPS bypass)
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
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
        ]
        SecItemDelete(query as CFDictionary)
        return SecItemAdd(query as CFDictionary, nil)
    }

    static func load(key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
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
    var accentColor: Color = Color(red: 0.3, green: 0.8, blue: 0.95)

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
    var accentColor: Color = Color(red: 0.3, green: 0.8, blue: 0.95)
    var backgroundColor: Color = Color(red: 0.12, green: 0.12, blue: 0.22).opacity(0.3)

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
enum LearnMoreContentType {
    case url
    case email
    case general
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
// You confirmed: 1 = safe
func predictURLSafety(from urlString: String) -> AssessmentResult? {
    guard let url = URL(string: urlString), let host = url.host else {
        return nil
    }

    let length = Int64(urlString.count)
    let has_https = Int64(url.scheme?.lowercased() == "https" ? 1 : 0)
    let num_dots = Int64(urlString.filter { $0 == "." }.count)
    let has_ip = Int64(host.split(separator: ".").allSatisfy { $0.allSatisfy(\Character.isNumber) } ? 1 : 0)
    let path_length = Int64(url.path.count)

    do {
        let model = try URL_Diagnoser_1(configuration: .init())
        let input = URL_Diagnoser_1Input(
            length: length,
            has_https: has_https,
            num_dots: num_dots,
            has_ip: has_ip,
            path_length: path_length
        )
        let prediction = try model.prediction(input: input)
        return prediction.Label == 1 ? .safe : .unsafe
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
        let role: String?
        let parts: [Part]
        init(role: String? = nil, parts: [Part]) {
            self.role = role
            self.parts = parts
        }
    }

    struct Part: Codable { let text: String }

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

        struct Part: Codable { let text: String? }
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

    Respond with exactly one word:
    Safe
    Unsafe
    Suspicious


    Text to analyze: \"\(text)\"
    """

    let body = GeminiRequestBody(
        contents: [GeminiRequestBody.Content(parts: [GeminiRequestBody.Part(text: prompt)])],
        generationConfig: GeminiRequestBody.GenerationConfig(temperature: 0.1, topP: 1.0, topK: 1, maxOutputTokens: 1000),
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

            if let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode != 200 {
                print("Gemini API HTTP Error: \(httpResponse.statusCode)")
                if let errorResponseString = String(data: data, encoding: .utf8) {
                    print("Error Response Body: \(errorResponseString)")
                }
                DispatchQueue.main.async { completion(nil) }
                return
            }

            do {
                let geminiResponse = try JSONDecoder().decode(GeminiResponseBody.self, from: data)

                if let promptFeedback = geminiResponse.promptFeedback, let safetyRatings = promptFeedback.safetyRatings, !safetyRatings.isEmpty {
                    DispatchQueue.main.async { completion(.unsafe) }
                    return
                }

                if let firstCandidate = geminiResponse.candidates?.first,
                   let responseText = firstCandidate.content.parts?.first?.text {
                    let trimmed = responseText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                    switch trimmed {
                    case "safe": DispatchQueue.main.async { completion(.safe) }
                    case "unsafe": DispatchQueue.main.async { completion(.unsafe) }
                    case "suspicious": DispatchQueue.main.async { completion(.suspicious) }
                    default:
                        print("Unexpected Gemini response: \(trimmed)")
                        DispatchQueue.main.async { completion(nil) }
                    }
                } else {
                    DispatchQueue.main.async { completion(.suspicious) }
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

    var contents: [GeminiRequestBody.Content] = []
    for turn in history {
        if let role = turn["role"], let text = turn["text"] {
            contents.append(GeminiRequestBody.Content(role: role, parts: [GeminiRequestBody.Part(text: text)]))
        }
    }
    contents.append(GeminiRequestBody.Content(role: "user", parts: [GeminiRequestBody.Part(text: message)]))

    let body = GeminiRequestBody(
        contents: contents,
        generationConfig: GeminiRequestBody.GenerationConfig(temperature: 0.7, topP: 1.0, topK: 40, maxOutputTokens: 2500),
        safetySettings: [
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
                DispatchQueue.main.async { completion("Network error. Please try again.", nil) }
                return
            }

            guard let data = data else {
                DispatchQueue.main.async { completion("No response data.", nil) }
                return
            }

            if let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode != 200 {
                DispatchQueue.main.async { completion("API error (\(httpResponse.statusCode)).", nil) }
                return
            }

            do {
                let geminiResponse = try JSONDecoder().decode(GeminiResponseBody.self, from: data)

                if let promptFeedback = geminiResponse.promptFeedback, let safetyRatings = promptFeedback.safetyRatings, !safetyRatings.isEmpty {
                    DispatchQueue.main.async { completion("Your message was flagged by safety systems. Please try rephrasing.", .unsafe) }
                    return
                }

                if let firstCandidate = geminiResponse.candidates?.first,
                   let responseText = firstCandidate.content.parts?.first?.text {
                    DispatchQueue.main.async { completion(responseText, .safe) }
                } else {
                    DispatchQueue.main.async { completion("Could not get a clear response from AI. Please try again.", .suspicious) }
                }
            } catch {
                DispatchQueue.main.async { completion("Failed to process AI response.", nil) }
            }
        }.resume()
    } catch {
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
            primaryBackgroundColor.ignoresSafeArea()
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
                        .font(.system(size: 15))
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
                        .font(.system(size: 15))
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
                        .font(.system(size: 15))
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
                    Text("Could not determine safety. Exercise extreme caution or avoid completely.")
                        .font(.system(size: 15))
                        .foregroundColor(textColor.opacity(0.8))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }

                Button("Back to Start") {
                    navState.isQuestionnaireSubmitted = false
                    navState.isURLSubmitted = false
                    navState.chatGPTResultSafe = nil
                    navState.isAIResultSafe = nil
                    navState.modelAssessment = nil
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
            primaryBackgroundColor.ignoresSafeArea()

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
                            Image(systemName: "checkmark.circle.fill").resizable().frame(width: 50, height: 50).foregroundColor(.green)
                            Text("Assessment: Safe!").font(.system(size: 24, weight: .semibold, design: .rounded)).foregroundColor(.green)
                            Text(LearnMoreText(for: .safe, type: .email)).font(.system(size: 15)).foregroundColor(textColor.opacity(0.8)).multilineTextAlignment(.center).padding(.horizontal)
                        case .unsafe:
                            Image(systemName: "xmark.octagon.fill").resizable().frame(width: 50, height: 50).foregroundColor(.red)
                            Text("Assessment: Unsafe!").font(.system(size: 24, weight: .semibold, design: .rounded)).foregroundColor(.red)
                            Text(LearnMoreText(for: .unsafe, type: .email)).font(.system(size: 15)).foregroundColor(textColor.opacity(0.8)).multilineTextAlignment(.center).padding(.horizontal)
                        case .suspicious:
                            Image(systemName: "questionmark.circle.fill").resizable().frame(width: 50, height: 50).foregroundColor(.orange)
                            Text("Assessment: Suspicious!").font(.system(size: 24, weight: .semibold, design: .rounded)).foregroundColor(.orange)
                            Text(LearnMoreText(for: .suspicious, type: .email)).font(.system(size: 15)).foregroundColor(textColor.opacity(0.8)).multilineTextAlignment(.center).padding(.horizontal)
                        }
                    }.padding(.top, 20)
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
            primaryBackgroundColor.ignoresSafeArea()

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
                        .overlay(RoundedRectangle(cornerRadius: 15).stroke(accentColor, lineWidth: 2))
                        .padding(.horizontal)
                }
                .padding(.top, 100)

                Button("Continue") {
                    guard let url = URL(string: urlText) else {
                        navState.modelAssessment = nil
                        navState.isAIResultSafe = nil
                        navState.skipAIURLCheck = false
                        navState.isURLSubmitted = false
                        print("Invalid URL.")
                        return
                    }

                    // HTTPS AUTO-BYPASS (requested): treat https as Safe and skip Gemini.
                    if url.scheme?.lowercased() == "https" {
                        navState.modelAssessment = .safe              // treat as model-safe for downstream logic
                        navState.isAIResultSafe = true                // legacy flag
                        navState.skipAIURLCheck = true                // ensures we won't call Gemini in Questionnaire step
                        navState.isURLSubmitted = true
                        print("HTTPS detected: Auto-marking Safe and skipping Gemini.")
                        return
                    }

                    // Otherwise run the local Core ML model and prioritize its output.
                    if let modelResult = predictURLSafety(from: urlText) {
                        navState.modelAssessment = modelResult
                        navState.isAIResultSafe = (modelResult == .safe)
                        navState.skipAIURLCheck = false               // model ran; we may still consult Gemini as secondary
                        navState.isURLSubmitted = true
                        print("Local AI Model assessment (URL): \(modelResult)")
                    } else {
                        navState.modelAssessment = nil
                        navState.isAIResultSafe = nil
                        navState.skipAIURLCheck = false
                        navState.isURLSubmitted = false
                        print("Prediction failed or invalid URL for local AI model. Cannot proceed.")
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
                    navState.modelAssessment = nil
                }
                .buttonStyle(SmallCyberBackButton(accentColor: accentColor, backgroundColor: secondaryBackgroundColor.opacity(0.3)))
                .padding(.top, 5)

                Spacer()
            }
            .navigationDestination(isPresented: $navState.isURLSubmitted) {
                QuestionnaireView(url: urlText, navState: navState)
                    .transition(.opacity)
                    .animation(.easeInOut(duration: 0.5), value: navState.isURLSubmitted)
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

    private var isAnyQuestionAnswered: Bool {
        questions.contains(where: { $0.answer != nil })
    }

    var body: some View {
        ZStack {
            primaryBackgroundColor.ignoresSafeArea()

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
                                .foregroundColor(textColor)
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
                                .opacity(0.8)
                        }
                    }
                    .padding(.horizontal)
                    .padding(.bottom, 20)
                }
                .background(primaryBackgroundColor)
                .scrollContentBackground(.hidden)

                Button {
                    // If HTTPS bypass was used, we don't call Gemini here.
                    if navState.skipAIURLCheck {
                        finalizeDecision(modelFirst: navState.modelAssessment, gemini: nil)
                        navState.isQuestionnaireSubmitted = true
                        return
                    }

                    isLoadingGeminiCheck = true
                    Task {
                        await withCheckedContinuation { continuation in
                            callGeminiAPI(for: userText) { gem in
                                navState.chatGPTResultSafe = gem
                                continuation.resume()
                            }
                        }
                        isLoadingGeminiCheck = false
                        finalizeDecision(modelFirst: navState.modelAssessment, gemini: navState.chatGPTResultSafe)
                        navState.isQuestionnaireSubmitted = true
                    }
                } label: {
                    if isLoadingGeminiCheck {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: textColor))
                            .padding(.vertical, 8)
                            .padding(.horizontal, 15)
                    } else {
                        Text(isAnyQuestionAnswered ? "Submit" : "Skip Questionnaire")
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
                    navState.modelAssessment = nil
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

    // Model-first decision logic
    private func finalizeDecision(modelFirst: AssessmentResult?, gemini: AssessmentResult?) {
        let yesAnswersCount = questions.filter { $0.answer == .yes }.count

        if let modelResult = modelFirst {
            switch modelResult {
            case .unsafe:
                navState.assessmentResult = .unsafe // hard-stop: model unsafe overrides
            case .safe:
                // Only soften to suspicious with strong red flags or Gemini=unsafe
                if gemini == .unsafe || yesAnswersCount >= 3 {
                    navState.assessmentResult = .suspicious
                } else {
                    navState.assessmentResult = .safe
                }
            case .suspicious:
                if gemini == .unsafe || yesAnswersCount >= 2 {
                    navState.assessmentResult = .unsafe
                } else {
                    navState.assessmentResult = .suspicious
                }
            }
        } else {
            // Fallback (no model result)
            let localAIApproved = navState.isAIResultSafe ?? false
            if localAIApproved && gemini == .safe && yesAnswersCount == 0 {
                navState.assessmentResult = .safe
            } else if !localAIApproved || gemini == .unsafe || yesAnswersCount >= 3 {
                navState.assessmentResult = .unsafe
            } else {
                navState.assessmentResult = .suspicious
            }
        }
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

                VStack(alignment: .leading, spacing: 10) {
                    Text("Generated Password:")
                        .font(.headline)
                        .foregroundColor(textColor.opacity(0.8))

                    Text(generatedPassword.isEmpty ? "Tap 'Generate' to create a password" : generatedPassword)
                        .font(.title2).fontWeight(.medium)
                        .foregroundColor(textColor)
                        .padding()
                        .frame(maxWidth: .infinity)
                        .background(secondaryBackgroundColor)
                        .cornerRadius(15)
                        .overlay(RoundedRectangle(cornerRadius: 15).stroke(accentColor.opacity(0.7), lineWidth: 2))
                        .padding(.horizontal)
                        .multilineTextAlignment(.center)
                }

                VStack(alignment: .leading) {
                    Text("Password Length: \(Int(passwordLength))")
                        .font(.subheadline)
                        .foregroundColor(textColor)

                    Slider(value: $passwordLength, in: 8...32, step: 1) {
                        Text("Length")
                    } minimumValueLabel: { Text("8") } maximumValueLabel: { Text("32") }
                        .tint(accentColor)
                }
                .padding(.horizontal)

                VStack(alignment: .leading, spacing: 15) {
                    Toggle(isOn: $includeUppercase) { Text("Include Uppercase (A-Z)") }
                    Toggle(isOn: $includeLowercase) { Text("Include Lowercase (a-z)") }
                    Toggle(isOn: $includeNumbers) { Text("Include Numbers (0-9)") }
                    Toggle(isOn: $includeSymbols) { Text("Include Symbols (!@#$...)") }
                }
                .font(.body)
                .foregroundColor(textColor)
                .toggleStyle(SwitchToggleStyle(tint: accentColor))
                .padding(.horizontal)

                HStack(spacing: 20) {
                    Button("Generate Password") { generatePassword() }
                        .buttonStyle(CyberButtonStyle(accentColor: accentColor))

                    Button("Copy") {
                        UIPasteboard.general.string = generatedPassword
                        showCopiedMessage = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { showCopiedMessage = false }
                    }
                    .buttonStyle(CyberButtonStyle(accentColor: accentColor))
                    .opacity(generatedPassword.isEmpty ? 0.5 : 1.0)
                    .disabled(generatedPassword.isEmpty)
                }

                if showCopiedMessage {
                    Text("Copied to clipboard!").font(.caption).foregroundColor(.green)
                        .transition(.opacity).animation(.easeInOut, value: showCopiedMessage)
                }

                Spacer()

                Button("Back to Home") { navState.showPasswordMaker = false }
                    .buttonStyle(SmallCyberBackButton(accentColor: accentColor, backgroundColor: secondaryBackgroundColor.opacity(0.3)))
                    .padding(.bottom, 20)
            }
            .padding(.vertical)
        }
        .onAppear { generatePassword() }
        .navigationBarBackButtonHidden(true)
    }

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

        for char in requiredChars.shuffled() {
            if password.count < passwordLengthInt { password.append(char) }
        }

        while password.count < passwordLengthInt {
            if let randomChar = characterPool.randomElement() { password.append(randomChar) }
        }

        generatedPassword = String(password.shuffled())
    }
}

// MARK: - Password Storage System
struct StoredPassword: Identifiable, Codable {
    let id: UUID
    var service: String
    var username: String
    var encryptedData: Data
    var notes: String?

    init(id: UUID = UUID(), service: String, username: String, encryptedData: Data, notes: String?) {
        self.id = id
        self.service = service
        self.username = username
        self.encryptedData = encryptedData
        self.notes = notes
    }
}

extension Data {
    static func random(byteCount: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        _ = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
        return Data(bytes)
    }
}

class PasswordStorage: ObservableObject {
    @Published var passwords: [StoredPassword] = []

    private var masterPasswordHash: Data?
    private let masterPasswordHashKey = KeychainManager.masterPasswordAccount
    private let encryptionSaltKey = "com.YourApp.EncryptionSalt"

    init() {
        self.masterPasswordHash = KeychainManager.load(key: masterPasswordHashKey)
        if self.masterPasswordHash != nil {
            print("PasswordStorage: Master password hash loaded from Keychain.")
        } else {
            print("PasswordStorage: No master password hash found in Keychain on launch.")
        }
        loadPasswords()
    }

    func setMasterPassword(password: String) -> Bool {
        guard let passwordData = password.data(using: .utf8) else { return false }
        let salt = Data.random(byteCount: 16)
        UserDefaults.standard.set(salt, forKey: encryptionSaltKey)

        guard let derivedKey = Self.deriveKeyFromPassword(password: passwordData, salt: salt) else {
            print("Failed to derive key for master password.")
            return false
        }
        let newHash = Data(derivedKey)

        let status = KeychainManager.save(key: masterPasswordHashKey, data: newHash)
        if status == errSecSuccess {
            self.masterPasswordHash = newHash
            print("Master password set successfully and saved to Keychain.")
            return true
        } else {
            print("Failed to save master password to Keychain: \(status)")
            return false
        }
    }

    func verifyMasterPassword(password: String) -> Bool {
        guard let storedHash = self.masterPasswordHash else {
            print("No master password hash in memory; reloading.")
            self.masterPasswordHash = KeychainManager.load(key: masterPasswordHashKey)
            guard let reloadedHash = self.masterPasswordHash else { return false }
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
        if !matches { print("Master password verification failed.") }
        return matches
    }

    func hasMasterPassword() -> Bool {
        return self.masterPasswordHash != nil || KeychainManager.load(key: masterPasswordHashKey) != nil
    }

    func resetMasterPassword() {
        let status = KeychainManager.delete(key: masterPasswordHashKey)
        if status == errSecSuccess {
            self.masterPasswordHash = nil
            print("Master password reset successfully.")
            self.passwords = []
            UserDefaults.standard.removeObject(forKey: "storedPasswords")
            UserDefaults.standard.removeObject(forKey: encryptionSaltKey)
        } else {
            print("Failed to delete master password from Keychain: \(status)")
        }
    }

    private func getEncryptionKey() throws -> SymmetricKey {
        guard let masterDerivedKeyData = self.masterPasswordHash else { throw PasswordStorageError.masterPasswordNotSet }
        guard let salt = UserDefaults.standard.data(forKey: encryptionSaltKey) else { throw PasswordStorageError.encryptionSaltMissing }

        let symmetricKey = SymmetricKey(data: masterDerivedKeyData)
        let derivedEncryptionKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: symmetricKey,
            salt: salt,
            outputByteCount: 32
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
            self.passwords = []
        }
    }

    func encryptPassword(plaintext: String) -> Data? {
        guard let plaintextData = plaintext.data(using: .utf8) else { return nil }
        do {
            let key = try getEncryptionKey()
            let sealedBox = try AES.GCM.seal(plaintextData, using: key)
            return sealedBox.combined
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
        let newPassword = StoredPassword(service: service, username: username, encryptedData: encryptedData, notes: notes)
        passwords.append(newPassword)
        savePasswords()
    }

    func updatePassword(id: UUID, service: String, username: String, passwordText: String, notes: String?) {
        if let index = passwords.firstIndex(where: { $0.id == id }) {
            guard let encryptedData = encryptPassword(plaintext: passwordText) else {
                print("Failed to encrypt password for updating.")
                return
            }
            passwords[index] = StoredPassword(id: id, service: service, username: username, encryptedData: encryptedData, notes: notes)
            savePasswords()
        }
    }

    func deletePassword(at offsets: IndexSet) {
        passwords.remove(atOffsets: offsets)
        savePasswords()
    }

    static func deriveKeyFromPassword(password: Data, salt: Data) -> Data? {
        let iterations = 100_000
        let keyLength = kCCKeySizeAES256

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
    @State private var showingResetConfirmation = false

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

                Button("Forgot Master Password?") { showingResetConfirmation = true }
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

            Button("Back to Home") { navState.showPasswordStorage = false }
                .buttonStyle(SmallCyberBackButton(accentColor: accentColor, backgroundColor: secondaryBackgroundColor.opacity(0.3)))
                .padding(.bottom, 20)
        }
        .padding()
        .background(primaryBackgroundColor.ignoresSafeArea())
        .alert("Authentication Failed", isPresented: $showingAlert) {
            Button("OK") { }
        } message: { Text(alertMessage) }
        .alert("Reset Master Password", isPresented: $showingResetConfirmation) {
            Button("Reset", role: .destructive) {
                passwordStorage.resetMasterPassword()
                isAuthenticated = false
            }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("This will delete your current master password and ALL stored passwords. You will need to set up a new master password. Are you sure?")
        }
    }
}

// MARK: - PasswordStorageView (Main Password List)
struct PasswordStorageView: View {
    @ObservedObject var navState: NavigationState
    @EnvironmentObject var passwordStorage: PasswordStorage
    @State private var showingAddEditSheet = false
    @State private var selectedPassword: StoredPassword? = nil
    @State private var isUnlocked = false
    @State private var masterPasswordSetup = false

    let primaryBackgroundColor = Color(red: 0.08, green: 0.08, blue: 0.15)
    let secondaryBackgroundColor = Color(red: 0.12, green: 0.12, blue: 0.22)
    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let textColor = Color.white

    var body: some View {
        ZStack {
            primaryBackgroundColor.ignoresSafeArea()

            VStack {
                if !passwordStorage.hasMasterPassword() {
                    SetMasterPasswordView(masterPasswordSetup: $masterPasswordSetup, isParentUnlocked: $isUnlocked)
                        .environmentObject(passwordStorage)
                        .environmentObject(navState)
                } else if !isUnlocked {
                    TwoFactorAuthView(isAuthenticated: $isUnlocked)
                        .environmentObject(passwordStorage)
                        .environmentObject(navState)
                } else {
                    List {
                        ForEach(passwordStorage.passwords) { pwd in
                            VStack(alignment: .leading, spacing: 5) {
                                Text(pwd.service).font(.headline).foregroundColor(accentColor)
                                Text("Username: \(pwd.username)").font(.subheadline).foregroundColor(textColor.opacity(0.9))
                                HStack {
                                    Text("Password: \(passwordStorage.getDecryptedPassword(for: pwd))")
                                        .font(.subheadline).foregroundColor(textColor.opacity(0.8))
                                    Button {
                                        UIPasteboard.general.string = passwordStorage.getDecryptedPassword(for: pwd)
                                    } label: {
                                        Image(systemName: "doc.on.doc").foregroundColor(accentColor)
                                    }
                                }
                                if let notes = pwd.notes, !notes.isEmpty {
                                    Text("Notes: \(notes)").font(.caption).foregroundColor(textColor.opacity(0.7))
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
                        isUnlocked = false
                    }
                    .buttonStyle(SmallCyberBackButton(accentColor: accentColor, backgroundColor: secondaryBackgroundColor.opacity(0.3)))
                    .padding(.bottom, 20)

                    #if DEBUG
                    Button("DEBUG: Reset Master Password & All Data") {
                        passwordStorage.resetMasterPassword()
                        isUnlocked = false
                        masterPasswordSetup = false
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
            
            .navigationBarBackButtonHidden(true)
        }
    }
}

// MARK: - SetMasterPasswordView
struct SetMasterPasswordView: View {
    @EnvironmentObject var passwordStorage: PasswordStorage
    @Binding var masterPasswordSetup: Bool
    @Binding var isParentUnlocked: Bool
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
                        masterPasswordSetup = true
                        isParentUnlocked = true
                    } else {
                        alertMessage = "Failed to set master password. Please try again."
                        showingAlert = true
                    }
                }
            }
            .buttonStyle(CyberButtonStyle(accentColor: .green))
            .padding(.horizontal)
            Spacer()

            Button("Back to Home") { navState.showPasswordStorage = false }
                .buttonStyle(SmallCyberBackButton(accentColor: accentColor, backgroundColor: secondaryBackgroundColor.opacity(0.3)))
                .padding(.bottom, 20)
        }
        .padding()
        .background(primaryBackgroundColor.ignoresSafeArea())
        .alert("Error", isPresented: $showingAlert) { Button("OK") { } } message: { Text(alertMessage) }
    }
}

// MARK: - AddEditPasswordView
struct AddEditPasswordView: View {
    @Environment(\.dismiss) var dismiss
    @EnvironmentObject var passwordStorage: PasswordStorage
    @Binding var password: StoredPassword?

    @State private var service: String = ""
    @State private var username: String = ""
    @State private var plaintextPassword: String = ""
    @State private var notes: String = ""

    let primaryBackgroundColor = Color(red: 0.08, green: 0.08, blue: 0.15)
    let secondaryBackgroundColor = Color(red: 0.12, green: 0.12, blue: 0.22)
    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let textColor = Color.white

    var body: some View {
        NavigationView {
            Form {
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
            .scrollContentBackground(.hidden)
            .background(primaryBackgroundColor)
            .navigationTitle(password == nil ? "Add Password" : "Edit Password")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") { dismiss() }.foregroundColor(accentColor)
                }
            }
            .onAppear {
                if let pwd = password {
                    service = pwd.service
                    username = pwd.username
                    plaintextPassword = passwordStorage.getDecryptedPassword(for: pwd)
                    notes = pwd.notes ?? ""
                }
            }
        }
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
                                            .background(RoundedRectangle(cornerRadius: 10).fill(secondaryBackgroundColor.opacity(0.7)))
                                        }
                                    }
                                }
                                .padding(.horizontal)
                            }
                        }
                        .padding(.bottom, 20)
                    }
                    .background(primaryBackgroundColor)
                    .scrollContentBackground(.hidden)

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
        if percentage >= 0.8 { return .safe }
        else if percentage >= 0.5 { return .suspicious }
        else { return .unsafe }
    }

    var body: some View {
        VStack(spacing: 25) {
            Text("Quiz Results").font(.largeTitle).fontWeight(.bold).foregroundColor(textColor)

            Text("You scored \(score) out of \(totalQuestions)!")
                .font(.title2)
                .foregroundColor(textColor.opacity(0.9))

            Image(systemName: resultIcon).resizable().frame(width: 80, height: 80).foregroundColor(resultColor)

            Text(LearnMoreText(for: assessmentResult, type: .general))
                .font(.body).foregroundColor(textColor.opacity(0.8))
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            Button("Retake Quiz") {
                navState.showMiniQuiz = false
            }
            .buttonStyle(CyberButtonStyle(accentColor: accentColor))
        }
        .padding()
        .background(secondaryBackgroundColor)
        .cornerRadius(20)
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(primaryBackgroundColor.ignoresSafeArea())
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
                        ForEach(chatHistory, id: \.self.debugDescription) { message in
                            ChatBubble(text: message["text"] ?? "", isUser: message["role"] == "user")
                        }
                        if isLoadingResponse {
                            ProgressView().progressViewStyle(CircularProgressViewStyle(tint: accentColor)).padding(.horizontal)
                        }
                    }
                    .padding()
                    .frame(maxWidth: .infinity)
                }
                .background(secondaryBackgroundColor.opacity(0.7))
                .cornerRadius(15)
                .padding(.horizontal)

                HStack {
                    TextField("Ask about a situation...", text: $messageText, axis: .vertical)
                        .padding(.vertical, 10).padding(.horizontal)
                        .background(secondaryBackgroundColor).cornerRadius(10)
                        .foregroundColor(textColor).accentColor(accentColor)
                        .font(.system(size: 16, design: .rounded))
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(accentColor, lineWidth: 1))
                        .frame(minHeight: 40).frame(maxWidth: .infinity)

                    Button { sendMessage() } label: {
                        Image(systemName: "paperplane.fill")
                            .font(.title2).padding(8)
                            .background(accentColor).foregroundColor(.white).cornerRadius(10)
                    }
                    .disabled(messageText.isEmpty || isLoadingResponse)
                }
                .padding()

                Button("Back to Home") {
                    navState.showGeminiChat = false
                    chatHistory = []
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
        messageText = ""

        var apiHistory: [[String: String]] = []
        for msg in chatHistory {
            if msg["role"] == "user" || msg["role"] == "model" {
                apiHistory.append(["role": msg["role"]!, "text": msg["text"]!])
            }
        }

        callGeminiChatAPI(for: userMessage, history: apiHistory) { response, _ in
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
            if isUser { Spacer() }
            Text(text)
                .padding(10)
                .background(isUser ? accentColor : Color.gray.opacity(0.3))
                .foregroundColor(textColor)
                .cornerRadius(15)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 250, alignment: isUser ? .trailing : .leading)
            if !isUser { Spacer() }
        }
    }
}

// MARK: - Home Screen
struct HomeView: View {
    @StateObject private var navState = NavigationState()
    @StateObject private var passwordStorage = PasswordStorage()

    let primaryBackgroundColor = Color(red: 0.08, green: 0.08, blue: 0.15)
    let secondaryBackgroundColor = Color(red: 0.12, green: 0.12, blue: 0.22)
    let accentColor = Color(red: 0.3, green: 0.8, blue: 0.95)
    let textColor = Color.white

    var body: some View {
        NavigationStack {
            ZStack {
                primaryBackgroundColor.ignoresSafeArea()

                VStack(spacing: 30) {
                    Spacer()

                    Text("Cyber-Check")
                        .font(.system(size: 44, weight: .bold, design: .rounded))
                        .foregroundColor(accentColor)
                        .shadow(color: accentColor.opacity(0.7), radius: 15)
                        .padding(.bottom, 20)

                    VStack(spacing: 20) {
                        Button("Check URL Safety") {
                            // Reset
                            navState.isURLSubmitted = false
                            navState.isQuestionnaireSubmitted = false
                            navState.isAIResultSafe = nil
                            navState.chatGPTResultSafe = nil
                            navState.skipAIURLCheck = false
                            navState.assessmentResult = nil
                            navState.modelAssessment = nil

                            navState.showURLCheck = true
                            navState.showEmailCheck = false
                            navState.showPasswordMaker = false
                            navState.showPasswordStorage = false
                            navState.showMiniQuiz = false
                            navState.showGeminiChat = false
                        }
                        .buttonStyle(CyberButtonStyle(accentColor: accentColor))

                        Button("Check Email Safety") {
                            navState.isURLSubmitted = false
                            navState.isQuestionnaireSubmitted = false
                            navState.isAIResultSafe = nil
                            navState.chatGPTResultSafe = nil
                            navState.skipAIURLCheck = false
                            navState.assessmentResult = nil
                            navState.modelAssessment = nil

                            navState.showURLCheck = false
                            navState.showPasswordMaker = false
                            navState.showPasswordStorage = false
                            navState.showMiniQuiz = false
                            navState.showGeminiChat = false
                            navState.showEmailCheck = true
                        }
                        .buttonStyle(CyberButtonStyle(accentColor: accentColor))

                        Button("Strong Password Maker") {
                            navState.isURLSubmitted = false
                            navState.isQuestionnaireSubmitted = false
                            navState.isAIResultSafe = nil
                            navState.chatGPTResultSafe = nil
                            navState.skipAIURLCheck = false
                            navState.assessmentResult = nil
                            navState.modelAssessment = nil

                            navState.showURLCheck = false
                            navState.showEmailCheck = false
                            navState.showPasswordStorage = false
                            navState.showMiniQuiz = false
                            navState.showGeminiChat = false
                            navState.showPasswordMaker = true
                        }
                        .buttonStyle(CyberButtonStyle(accentColor: accentColor))

                        Button("Secure Password Storage") {
                            navState.isURLSubmitted = false
                            navState.isQuestionnaireSubmitted = false
                            navState.isAIResultSafe = nil
                            navState.chatGPTResultSafe = nil
                            navState.skipAIURLCheck = false
                            navState.assessmentResult = nil
                            navState.modelAssessment = nil

                            navState.showURLCheck = false
                            navState.showEmailCheck = false
                            navState.showPasswordMaker = false
                            navState.showMiniQuiz = false
                            navState.showGeminiChat = false
                            navState.showPasswordStorage = true
                        }
                        .buttonStyle(CyberButtonStyle(accentColor: accentColor))

                        Button("Cyber-Safety Mini Quiz") {
                            navState.isURLSubmitted = false
                            navState.isQuestionnaireSubmitted = false
                            navState.isAIResultSafe = nil
                            navState.chatGPTResultSafe = nil
                            navState.skipAIURLCheck = false
                            navState.assessmentResult = nil
                            navState.modelAssessment = nil

                            navState.showURLCheck = false
                            navState.showEmailCheck = false
                            navState.showPasswordMaker = false
                            navState.showPasswordStorage = false
                            navState.showGeminiChat = false
                            navState.showMiniQuiz = true
                        }
                        .buttonStyle(CyberButtonStyle(accentColor: accentColor))

                        Button("Chat with Cyber-AI") {
                            navState.isURLSubmitted = false
                            navState.isQuestionnaireSubmitted = false
                            navState.isAIResultSafe = nil
                            navState.chatGPTResultSafe = nil
                            navState.skipAIURLCheck = false
                            navState.assessmentResult = nil
                            navState.modelAssessment = nil

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

                    Text("")
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
                        .environmentObject(passwordStorage)
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
