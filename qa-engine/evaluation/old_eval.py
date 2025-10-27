import numpy as np
import nltk
from nltk.tokenize import sent_tokenize, word_tokenize
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sentence_transformers import SentenceTransformer
import textstat
import spacy
from collections import Counter
import math
import torch
from transformers import AutoTokenizer, AutoModel
import re

class SummaryEvaluator:
    def __init__(self):
        # Load models for semantic evaluation
        self.sentence_model = SentenceTransformer('all-MiniLM-L6-v2')
        self.nlp = spacy.load('en_core_web_sm')
        
        # Initialize BERT model for BERTScore-style evaluation
        self.bert_tokenizer = AutoTokenizer.from_pretrained('bert-base-uncased')
        self.bert_model = AutoModel.from_pretrained('bert-base-uncased')
        
    # =============================================================================
    # LINGUISTIC QUALITY METRICS
    # =============================================================================
    
    def calculate_perplexity(self, text, model_name='gpt2'):
        """Calculate perplexity using a language model"""
        from transformers import GPT2LMHeadModel, GPT2Tokenizer
        
        tokenizer = GPT2Tokenizer.from_pretrained(model_name)
        model = GPT2LMHeadModel.from_pretrained(model_name)
        
        # Add padding token
        tokenizer.pad_token = tokenizer.eos_token
        
        inputs = tokenizer.encode(text, return_tensors='pt', truncation=True, max_length=512)
        
        with torch.no_grad():
            outputs = model(inputs, labels=inputs)
            loss = outputs.loss
            perplexity = torch.exp(loss)
            
        return perplexity.item()
    
    def readability_metrics(self, text):
        """Calculate various readability metrics"""
        metrics = {
            'flesch_kincaid_grade': textstat.flesch_kincaid().grade_level(text),
            'flesch_reading_ease': textstat.flesch_reading_ease(text),
            'gunning_fog': textstat.gunning_fog(text),
            'automated_readability': textstat.automated_readability_index(text),
            'coleman_liau': textstat.coleman_liau_index(text),
            'avg_sentence_length': textstat.avg_sentence_length(text),
            'avg_syllables_per_word': textstat.avg_syllables_per_word(text)
        }
        return metrics
    
    def grammar_coherence_score(self, text):
        """Analyze grammar and syntactic coherence"""
        doc = self.nlp(text)
        
        # Count grammar errors (simplified)
        grammar_errors = 0
        total_tokens = len(doc)
        
        # Check for basic grammar patterns
        for token in doc:
            # Simple checks for common errors
            if token.pos_ == 'VERB' and token.tag_ in ['VBZ', 'VBP'] and token.head.tag_ in ['NNS']:
                grammar_errors += 1
        
        grammar_score = 1 - (grammar_errors / max(total_tokens, 1))
        
        # Coherence based on dependency parsing
        coherence_score = self._calculate_dependency_coherence(doc)
        
        return {
            'grammar_score': grammar_score,
            'coherence_score': coherence_score,
            'total_errors': grammar_errors
        }
    
    def _calculate_dependency_coherence(self, doc):
        """Calculate coherence based on dependency structure"""
        sentences = list(doc.sents)
        if len(sentences) <= 1:
            return 1.0
        
        coherence_scores = []
        
        for i in range(len(sentences) - 1):
            sent1_entities = set([ent.text.lower() for ent in sentences[i].ents])
            sent2_entities = set([ent.text.lower() for ent in sentences[i + 1].ents])
            
            # Entity overlap between consecutive sentences
            if sent1_entities or sent2_entities:
                overlap = len(sent1_entities.intersection(sent2_entities))
                total = len(sent1_entities.union(sent2_entities))
                coherence_scores.append(overlap / max(total, 1))
            else:
                coherence_scores.append(0.0)
        
        return np.mean(coherence_scores) if coherence_scores else 0.0
    
    def lexical_diversity(self, text):
        """Calculate lexical diversity metrics"""
        tokens = word_tokenize(text.lower())
        tokens = [token for token in tokens if token.isalpha()]
        
        if not tokens:
            return {'ttr': 0, 'mtld': 0, 'unique_words': 0}
        
        unique_tokens = set(tokens)
        
        # Type-Token Ratio
        ttr = len(unique_tokens) / len(tokens)
        
        # Measure of Textual Lexical Diversity (simplified)
        mtld = self._calculate_mtld(tokens)
        
        return {
            'type_token_ratio': ttr,
            'mtld': mtld,
            'unique_words': len(unique_tokens),
            'total_words': len(tokens)
        }
    
    def _calculate_mtld(self, tokens):
        """Simplified MTLD calculation"""
        if len(tokens) < 10:
            return 0
        
        ttr_threshold = 0.72
        segments = []
        current_segment = []
        
        for token in tokens:
            current_segment.append(token)
            if len(current_segment) > 10:
                unique_in_segment = set(current_segment)
                segment_ttr = len(unique_in_segment) / len(current_segment)
                
                if segment_ttr <= ttr_threshold:
                    segments.append(len(current_segment))
                    current_segment = []
        
        return np.mean(segments) if segments else 0
    
    # =============================================================================
    # SEMANTIC EVALUATION METRICS
    # =============================================================================
    
    def semantic_similarity_bert(self, source_text, summary_text):
        """Calculate semantic similarity using BERT embeddings"""
        # Get BERT embeddings
        source_embedding = self._get_bert_embedding(source_text)
        summary_embedding = self._get_bert_embedding(summary_text)
        
        # Calculate cosine similarity
        similarity = cosine_similarity(
            source_embedding.reshape(1, -1),
            summary_embedding.reshape(1, -1)
        )[0, 0]
        
        return similarity
    
    def _get_bert_embedding(self, text):
        """Get BERT embedding for text"""
        inputs = self.bert_tokenizer(text, return_tensors='pt', truncation=True, 
                                   max_length=512, padding=True)
        
        with torch.no_grad():
            outputs = self.bert_model(**inputs)
            # Use [CLS] token embedding or mean pooling
            embedding = outputs.last_hidden_state[:, 0, :].squeeze()  # CLS token
            
        return embedding.numpy()
    
    def sentence_transformer_similarity(self, source_text, summary_text):
        """Calculate semantic similarity using Sentence Transformers"""
        source_sentences = sent_tokenize(source_text)
        summary_sentences = sent_tokenize(summary_text)
        
        if not source_sentences or not summary_sentences:
            return 0.0
        
        # Get embeddings
        source_embeddings = self.sentence_model.encode(source_sentences)
        summary_embeddings = self.sentence_model.encode(summary_sentences)
        
        # Calculate sentence-level similarities
        similarities = cosine_similarity(source_embeddings, summary_embeddings)
        
        # Various aggregation strategies
        max_similarities = np.max(similarities, axis=0)  # Best match for each summary sentence
        avg_max_similarity = np.mean(max_similarities)
        
        # Coverage: how much of source is covered
        coverage = np.mean(np.max(similarities, axis=1))
        
        return {
            'avg_max_similarity': avg_max_similarity,
            'source_coverage': coverage,
            'similarity_matrix': similarities.tolist()
        }
    
    def information_coverage(self, source_text, summary_text):
        """Evaluate information coverage using TF-IDF and topic modeling"""
        # TF-IDF based coverage
        vectorizer = TfidfVectorizer(stop_words='english', max_features=1000)
        
        try:
            tfidf_matrix = vectorizer.fit_transform([source_text, summary_text])
            tfidf_similarity = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0, 0]
        except:
            tfidf_similarity = 0.0
        
        # Key phrase coverage
        source_doc = self.nlp(source_text)
        summary_doc = self.nlp(summary_text)
        
        # Extract key phrases (noun phrases and named entities)
        source_keyphrases = set()
        summary_keyphrases = set()
        
        for chunk in source_doc.noun_chunks:
            source_keyphrases.add(chunk.text.lower().strip())
        for ent in source_doc.ents:
            source_keyphrases.add(ent.text.lower().strip())
            
        for chunk in summary_doc.noun_chunks:
            summary_keyphrases.add(chunk.text.lower().strip())
        for ent in summary_doc.ents:
            summary_keyphrases.add(ent.text.lower().strip())
        
        # Calculate coverage
        if source_keyphrases:
            keyphrase_coverage = len(source_keyphrases.intersection(summary_keyphrases)) / len(source_keyphrases)
        else:
            keyphrase_coverage = 0.0
        
        return {
            'tfidf_similarity': tfidf_similarity,
            'keyphrase_coverage': keyphrase_coverage,
            'source_keyphrases_count': len(source_keyphrases),
            'summary_keyphrases_count': len(summary_keyphrases)
        }
    
    def factual_consistency_check(self, source_text, summary_text):
        """Basic factual consistency checking using entity matching"""
        source_doc = self.nlp(source_text)
        summary_doc = self.nlp(summary_text)
        
        # Extract entities
        source_entities = {(ent.text.lower(), ent.label_) for ent in source_doc.ents}
        summary_entities = {(ent.text.lower(), ent.label_) for ent in summary_doc.ents}
        
        # Check for contradictory information (simplified)
        consistent_entities = source_entities.intersection(summary_entities)
        summary_only_entities = summary_entities - source_entities
        
        if summary_entities:
            consistency_ratio = len(consistent_entities) / len(summary_entities)
        else:
            consistency_ratio = 1.0
        
        return {
            'consistency_ratio': consistency_ratio,
            'consistent_entities': len(consistent_entities),
            'total_summary_entities': len(summary_entities),
            'potentially_inconsistent': len(summary_only_entities)
        }
    
    # =============================================================================
    # COMPREHENSIVE EVALUATION
    # =============================================================================
    
    def evaluate_summary(self, source_text, summary_text):
        """Comprehensive evaluation of summary quality"""
        print("Evaluating summary...")
        
        results = {
            'linguistic_quality': {},
            'semantic_evaluation': {},
            'overall_scores': {}
        }
        
        # Linguistic Quality Metrics
        print("- Calculating linguistic quality metrics...")
        results['linguistic_quality']['readability'] = self.readability_metrics(summary_text)
        results['linguistic_quality']['lexical_diversity'] = self.lexical_diversity(summary_text)
        results['linguistic_quality']['grammar_coherence'] = self.grammar_coherence_score(summary_text)
        
        try:
            results['linguistic_quality']['perplexity'] = self.calculate_perplexity(summary_text)
        except Exception as e:
            results['linguistic_quality']['perplexity'] = f"Error: {str(e)}"
        
        # Semantic Evaluation Metrics
        print("- Calculating semantic similarity metrics...")
        results['semantic_evaluation']['bert_similarity'] = self.semantic_similarity_bert(source_text, summary_text)
        results['semantic_evaluation']['sentence_transformer'] = self.sentence_transformer_similarity(source_text, summary_text)
        results['semantic_evaluation']['information_coverage'] = self.information_coverage(source_text, summary_text)
        results['semantic_evaluation']['factual_consistency'] = self.factual_consistency_check(source_text, summary_text)
        
        # Calculate overall scores
        print("- Computing overall scores...")
        results['overall_scores'] = self._calculate_overall_scores(results)
        
        return results
    
    def _calculate_overall_scores(self, results):
        """Calculate aggregated overall scores"""
        scores = {}
        
        # Linguistic Quality Score (0-1)
        readability_score = max(0, min(1, (100 - results['linguistic_quality']['readability']['flesch_kincaid_grade']) / 20))
        diversity_score = results['linguistic_quality']['lexical_diversity']['type_token_ratio']
        coherence_score = results['linguistic_quality']['grammar_coherence']['coherence_score']
        
        scores['linguistic_quality_score'] = np.mean([readability_score, diversity_score, coherence_score])
        
        # Semantic Quality Score (0-1)
        bert_sim = results['semantic_evaluation']['bert_similarity']
        sent_trans_sim = results['semantic_evaluation']['sentence_transformer']['avg_max_similarity']
        coverage_score = results['semantic_evaluation']['information_coverage']['tfidf_similarity']
        consistency_score = results['semantic_evaluation']['factual_consistency']['consistency_ratio']
        
        scores['semantic_quality_score'] = np.mean([bert_sim, sent_trans_sim, coverage_score, consistency_score])
        
        # Overall Score
        scores['overall_score'] = (scores['linguistic_quality_score'] + scores['semantic_quality_score']) / 2
        
        return scores

# Example usage and demonstration
if __name__ == "__main__":
    # Example texts
    source_text = """
    Artificial intelligence has revolutionized many industries in recent years. Machine learning algorithms 
    can now process vast amounts of data and identify patterns that humans might miss. In healthcare, 
    AI systems help doctors diagnose diseases more accurately and quickly. In finance, algorithms detect 
    fraudulent transactions in real-time. The automotive industry has embraced AI for developing 
    autonomous vehicles. However, these advances also raise important ethical questions about privacy, 
    job displacement, and algorithmic bias that society must address.
    """
    
    summary_text = """
    AI has transformed multiple industries through machine learning algorithms that process large datasets 
    and find hidden patterns. Healthcare benefits from improved diagnosis, while finance uses AI for 
    fraud detection. The automotive sector develops self-driving cars using AI. Despite benefits, 
    ethical concerns about privacy and job losses need attention.
    """
    
    # Initialize evaluator
    evaluator = SummaryEvaluator()
    
    # Evaluate the summary
    evaluation_results = evaluator.evaluate_summary(source_text, summary_text)
    
    print("\n" + "="*60)
    print("SUMMARY EVALUATION RESULTS")
    print("="*60)
    
    # Display results
    print(f"\nOverall Score: {evaluation_results['overall_scores']['overall_score']:.3f}")
    print(f"Linguistic Quality: {evaluation_results['overall_scores']['linguistic_quality_score']:.3f}")
    print(f"Semantic Quality: {evaluation_results['overall_scores']['semantic_quality_score']:.3f}")