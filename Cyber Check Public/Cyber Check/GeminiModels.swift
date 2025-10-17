/*import Foundation

// MARK: - Gemini API Models

struct GeminiRequestBody: Encodable {
    let contents: [Content]
    let generationConfig: GenerationConfig?

    struct Content: Encodable {
        let parts: [Part]
    }

    struct Part: Encodable {
        let text: String
    }

    struct GenerationConfig: Encodable {
        let temperature: Double?
        let topP: Double?
        let topK: Int?
        let maxOutputTokens: Int?
        let stopSequences: [String]? = nil // Defaulted this to nil
    }
}

struct GeminiResponseBody: Decodable {
    let candidates: [Candidate]? // Make candidates optional
    let promptFeedback: PromptFeedback? // Add promptFeedback

    struct Candidate: Decodable {
        let content: Content
        let finishReason: String?
        let safetyRatings: [SafetyRating]?
    }

    struct Content: Decodable {
        let parts: [Part]
        let role: String?
    }

    struct Part: Decodable {
        let text: String
    }

    struct SafetyRating: Decodable {
        let category: String
        let probability: String
    }

    struct PromptFeedback: Decodable {
        let safetyRatings: [SafetyRating]?
    }
}
*/
