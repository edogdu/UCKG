import numpy as np
from nltk.tokenize import word_tokenize
from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
from rouge_score import rouge_scorer
from bert_score import score as bert_score
import argparse
import sys
import warnings
import json
import os

# Optional plotting
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    _PLOTTING_AVAILABLE = True
except Exception:
    _PLOTTING_AVAILABLE = False

# Optional QA factuality
try:
    from qafacteval import QAFactEval
except Exception:
    QAFactEval = None

class SummaryEvaluator:
    def __init__(self):
        # No heavy model init needed for the selected metrics
        self._qa_evaluator = None  # Lazy initialization for QAFactEval
        
    # =============================================================================
    # MAIN METRICS
    # =============================================================================

    def compute_rouge(self, source_text, summary_text):
        """Compute ROUGE-1/2/Lsum using rouge-score.
        Note: Ideally compare hypothesis to a reference summary; here, source is used as reference.
        """
        try:
            scorer = rouge_scorer.RougeScorer(['rouge1', 'rouge2', 'rougeLsum'], use_stemmer=True)
            scores = scorer.score(source_text, summary_text)
            return {
                'rouge1': {'precision': scores['rouge1'].precision, 'recall': scores['rouge1'].recall, 'f1': scores['rouge1'].fmeasure},
                'rouge2': {'precision': scores['rouge2'].precision, 'recall': scores['rouge2'].recall, 'f1': scores['rouge2'].fmeasure},
                'rougeLsum': {'precision': scores['rougeLsum'].precision, 'recall': scores['rougeLsum'].recall, 'f1': scores['rougeLsum'].fmeasure}
            }
        except Exception as e:
            return {'error': str(e)}

    def compute_bleu(self, source_text, summary_text):
        """Compute sentence-level BLEU with smoothing.
        Note: Ideally compare hypothesis to a reference summary; here, source is used as reference.
        """
        try:
            reference_tokens = [word_tokenize(source_text.lower())]
            hypothesis_tokens = word_tokenize(summary_text.lower())
            smoothie = SmoothingFunction().method3
            bleu4 = sentence_bleu(reference_tokens, hypothesis_tokens, smoothing_function=smoothie)
            bleu1 = sentence_bleu(reference_tokens, hypothesis_tokens, weights=(1, 0, 0, 0), smoothing_function=smoothie)
            bleu2 = sentence_bleu(reference_tokens, hypothesis_tokens, weights=(0.5, 0.5, 0, 0), smoothing_function=smoothie)
            bleu3 = sentence_bleu(reference_tokens, hypothesis_tokens, weights=(1/3, 1/3, 1/3, 0), smoothing_function=smoothie)
            return {'bleu1': bleu1, 'bleu2': bleu2, 'bleu3': bleu3, 'bleu4': bleu4}
        except Exception as e:
            return {'error': str(e)}

    def compute_bertscore(self, source_text, summary_text, model_type='microsoft/deberta-xlarge-mnli'):
        """Compute BERTScore P/R/F1 (rescaled) treating source as reference."""
        try:
            P, R, F1 = bert_score([summary_text], [source_text], model_type=model_type, rescale_with_baseline=True, lang='en')
            return {
                'precision': float(P.mean().item()),
                'recall': float(R.mean().item()),
                'f1': float(F1.mean().item())
            }
        except Exception as e:
            return {'error': str(e)}

    def compute_bertscore_precision_only(self, source_text, summary_text, model_type='microsoft/deberta-xlarge-mnli'):
        """Compute BERTScore precision only (rescaled)."""
        try:
            P, _, _ = bert_score([summary_text], [source_text], model_type=model_type, rescale_with_baseline=True, lang='en')
            return {'precision_only': float(P.mean().item())}
        except Exception as e:
            return {'error': str(e)}

    def _get_qa_evaluator(self):
        """Lazy initialize QAFactEval evaluator (heavy model loading)."""
        if QAFactEval is None:
            return None
        if self._qa_evaluator is None:
            self._qa_evaluator = QAFactEval(
                qa_model='deepset/roberta-base-squad2',
                entailment_model='ynie/roberta-large-snli_mnli_fever_anli_R1_R2_R3-nli',
                use_cuda=False
            )
        return self._qa_evaluator

    def qafacteval_score(self, source_text, summary_text):
        """Compute QA-based factual consistency via QAFactEval if available."""
        evaluator = self._get_qa_evaluator()
        if evaluator is None:
            return {'available': False, 'error': 'QAFactEval is not installed.'}
        try:
            scores = evaluator.score([summary_text], [source_text])
            return {'available': True, 'scores': scores[0] if isinstance(scores, list) else scores}
        except Exception as e:
            return {'available': False, 'error': str(e)}
    # =============================================================================
    # EVALUATION ENTRYPOINT (ONLY MAIN METRICS)
    # =============================================================================

    def evaluate_summary(self, source_text, summary_text):
        print("Evaluating summary (main metrics only)...")

        results = {
            'metrics': {}
        }

        # Compute requested metrics
        results['metrics']['rouge'] = self.compute_rouge(source_text, summary_text)
        results['metrics']['bleu'] = self.compute_bleu(source_text, summary_text)
        results['metrics']['bertscore'] = self.compute_bertscore(source_text, summary_text)
        results['metrics']['bertscore_precision_only'] = self.compute_bertscore_precision_only(source_text, summary_text)
        results['metrics']['qafacteval'] = self.qafacteval_score(source_text, summary_text)

        return results

def _print_scores(results):
    metrics = results.get('metrics', {})

    print("\n" + "="*60)
    print("MAIN METRICS")
    print("="*60)

    rouge = metrics.get('rouge', {})
    if rouge and isinstance(rouge, dict) and 'rouge1' in rouge:
        try:
            print(f"ROUGE F1 -> R1: {rouge['rouge1']['f1']:.3f}  R2: {rouge['rouge2']['f1']:.3f}  RLsum: {rouge['rougeLsum']['f1']:.3f}")
        except Exception:
            print(f"ROUGE: {rouge}")
    bleu = metrics.get('bleu', {})
    if bleu and 'bleu4' in bleu:
        print(f"BLEU -> 1: {bleu['bleu1']:.3f}  2: {bleu['bleu2']:.3f}  3: {bleu['bleu3']:.3f}  4: {bleu['bleu4']:.3f}")
    berts = metrics.get('bertscore', {})
    if berts and 'f1' in berts:
        print(f"BERTScore -> P: {berts['precision']:.3f}  R: {berts['recall']:.3f}  F1: {berts['f1']:.3f}")
    bp = metrics.get('bertscore_precision_only', {})
    if bp and 'precision_only' in bp:
        print(f"BERTScore (precision-only): {bp['precision_only']:.3f}")
    qafe = metrics.get('qafacteval', {})
    if qafe:
        if qafe.get('available'):
            print("QAFactEval: available")
        else:
            print("QAFactEval:", qafe.get('error', 'Unavailable'))


def _display_plots(results, title_prefix="Evaluation"):
    if not _PLOTTING_AVAILABLE:
        warnings.warn("Plotting libraries are not available. Install matplotlib and seaborn to enable plots.")
        return
    metrics = results.get('metrics', {})

    # Bar charts for ROUGE and BLEU and BERTScore
    rouge = metrics.get('rouge', {})
    if isinstance(rouge, dict) and 'rouge1' in rouge:
        plt.figure(figsize=(6, 4))
        vals = [rouge['rouge1']['f1'], rouge['rouge2']['f1'], rouge['rougeLsum']['f1']]
        sns.barplot(x=['ROUGE-1', 'ROUGE-2', 'ROUGE-Lsum'], y=vals)
        plt.ylim(0, 1)
        plt.title(f"{title_prefix}: ROUGE F1")
        plt.tight_layout()

    bleu = metrics.get('bleu', {})
    if isinstance(bleu, dict) and 'bleu4' in bleu:
        plt.figure(figsize=(6, 4))
        vals = [bleu['bleu1'], bleu['bleu2'], bleu['bleu3'], bleu['bleu4']]
        sns.barplot(x=['BLEU-1', 'BLEU-2', 'BLEU-3', 'BLEU-4'], y=vals)
        plt.ylim(0, 1)
        plt.title(f"{title_prefix}: BLEU Scores")
        plt.tight_layout()

    berts = metrics.get('bertscore', {})
    if isinstance(berts, dict) and 'f1' in berts:
        plt.figure(figsize=(6, 4))
        vals = [berts['precision'], berts['recall'], berts['f1']]
        sns.barplot(x=['Precision', 'Recall', 'F1'], y=vals)
        plt.ylim(0, 1)
        plt.title(f"{title_prefix}: BERTScore")
        plt.tight_layout()

    try:
        plt.show(block=False)  # Non-blocking for headless environments
    except Exception:
        plt.savefig('evaluation_plots.png', dpi=150, bbox_inches='tight')
        print("Note: Plots saved to evaluation_plots.png (use --no-plots to disable)")


def _read_text_from_arg_or_file(arg_text: str, arg_file: str, label: str) -> str:
    if arg_text:
        return arg_text
    if arg_file:
        try:
            with open(arg_file, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"Error reading {label} file: {e}")
            sys.exit(1)
    print(f"Missing {label}. Provide --{label.replace(' ', '-')} or --{label.replace(' ', '-')}-file")
    sys.exit(2)


def _load_evaluation_dataset(dataset_path: str) -> dict:
    """Load the evaluation dataset JSON file."""
    try:
        with open(dataset_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        print(f"Error: Dataset file not found: {dataset_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in dataset file: {e}")
        sys.exit(1)


def _get_sample_by_id(dataset: dict, sample_id: int) -> dict:
    """Extract a specific sample by ID from the dataset."""
    samples = dataset.get('samples', [])
    if not samples:
        print("Error: Dataset contains no samples.")
        sys.exit(1)
    
    for sample in samples:
        if sample.get('id') == sample_id:
            # Validate required fields
            required_fields = ['context', 'response']
            missing = [f for f in required_fields if not sample.get(f)]
            if missing:
                print(f"Warning: Sample {sample_id} missing fields: {missing}")
            return sample
    
    print(f"Error: Sample with ID {sample_id} not found in dataset.")
    available_ids = [s.get('id') for s in samples]
    print(f"Available IDs: {available_ids}")
    sys.exit(1)


def _print_metadata_info(sample: dict):
    """Print metadata information for the sample."""
    print("\n" + "="*60)
    print("SAMPLE METADATA")
    print("="*60)
    
    metadata = sample.get('metadata', {})
    node_info = metadata.get('node_info', {})
    
    print(f"Question ID: {sample.get('id')}")
    # Extract hop count from node_info
    hop_count = metadata.get('hop_count', {0})
    question_type = metadata.get('question_type', 'N/A')
    print(f"Question Type: {question_type}")
    print(f"Hop Count: {hop_count}")
    first_node = node_info.get('first_node', 'N/A')
    print(f"First Node: {first_node}")

    print("\nQuestion:")
    print(f"  {sample.get('question', 'N/A')[:200]}...")
    print()


def main():
    parser = argparse.ArgumentParser(description="Evaluate a summary against its source text.")
    parser.add_argument('--source-text', type=str, default=None, help='Source text string')
    parser.add_argument('--summary-text', type=str, default=None, help='Summary text string')
    parser.add_argument('--source-file', type=str, default=None, help='Path to a file containing the source text')
    parser.add_argument('--summary-file', type=str, default=None, help='Path to a file containing the summary text')
    parser.add_argument('--no-plots', action='store_true', help='Disable plots even if libraries are available')
    parser.add_argument('--title', type=str, default='Evaluation', help='Title prefix for plots')
    
    # Dataset mode arguments
    parser.add_argument('--id', type=int, default=None, help='Sample ID from evaluation dataset')
    parser.add_argument('--dataset', type=str, default='evaluation_dataset.json', 
                        help='Path to evaluation dataset JSON file')
    parser.add_argument('--list-ids', action='store_true', 
                        help='List all available sample IDs from dataset')

    args = parser.parse_args()

    # NLTK data safety check
    try:
        _ = word_tokenize("test")
    except Exception:
        import nltk
        try:
            print("Downloading NLTK 'punkt' tokenizer (first run only)...")
            nltk.download('punkt', quiet=True)
            print("✓ NLTK data ready.")
        except Exception as e:
            print(f"⚠ Warning: NLTK data download failed: {e}")

    # Handle --list-ids option
    if args.list_ids:
        dataset_path = args.dataset
        if not os.path.isabs(dataset_path):
            script_dir = os.path.dirname(os.path.abspath(__file__))
            dataset_path = os.path.join(script_dir, dataset_path)
        
        try:
            dataset = _load_evaluation_dataset(dataset_path)
            samples = dataset.get('samples', [])
            metadata_info = dataset.get('dataset_metadata', {})
            
            print("\n" + "="*60)
            print("DATASET INFORMATION")
            print("="*60)
            print(f"Total Questions: {metadata_info.get('total_questions', len(samples))}")
            print(f"Generation Date: {metadata_info.get('generation_date', 'N/A')}")
            print(f"Pipeline: {metadata_info.get('pipeline', 'N/A')}")
            print(f"\nAvailable Sample IDs: {[s.get('id') for s in samples]}")
            print(f"ID Range: {min([s.get('id') for s in samples])} - {max([s.get('id') for s in samples])}")
            print("="*60)
            sys.exit(0)
        except Exception as e:
            print(f"Error loading dataset for listing: {e}")
            sys.exit(1)
    
    # Check if dataset mode is active
    if args.id is not None:
        # Dataset mode: load from JSON
        dataset_path = args.dataset
        if not os.path.isabs(dataset_path):
            # Try relative to current script directory
            script_dir = os.path.dirname(os.path.abspath(__file__))
            dataset_path = os.path.join(script_dir, dataset_path)
        
        print(f"Loading dataset: {dataset_path}")
        dataset = _load_evaluation_dataset(dataset_path)
        
        sample = _get_sample_by_id(dataset, args.id)
        
        # Display metadata
        _print_metadata_info(sample)
        
        # Extract texts for evaluation
        source_text = sample.get('context', '')
        summary_text = sample.get('response', '')
        
        if not source_text or not summary_text:
            print("Error: Missing context or response in sample.")
            sys.exit(1)
        
        # Update title to include sample info
        if not args.title or args.title == 'Evaluation':
            args.title = f"Sample ID {args.id}"
    else:
        # Standard mode: read from args/files
        source_text = _read_text_from_arg_or_file(args.source_text, args.source_file, 'source-text')
        summary_text = _read_text_from_arg_or_file(args.summary_text, args.summary_file, 'summary-text')

    evaluator = SummaryEvaluator()
    results = evaluator.evaluate_summary(source_text, summary_text)
    _print_scores(results)

    if not args.no_plots:
        _display_plots(results, title_prefix=args.title)


if __name__ == "__main__":
    main()